from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from PIL import Image, ImageDraw, ImageFont

import io, base64, json, time
import redis, sqlite3
import random, string
import httpx as _httpx

from utils.remote_services import CA_URL
from utils.crypto_utils import verify_signature_with_pem
from utils.auth_utils import (hash_password, create_token, get_current_user,
                        require_role, create_challenge, pop_challenge)
from utils.remote_services import (ca_get_cert, ca_verify_cert, ca_issue_cert,
                        ca_revoke_cert, gateway_get_cert, gateway_process_payment)
from utils.constants import Role, OrderStatus, CertStatus

font = ImageFont.load_default(size=28)
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

app = FastAPI(title="E-Commerce Security System")
app.mount("/static", StaticFiles(directory="frontend"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "./database/ecommerce.db"

# ─── Part 1: Database ───

# Connect to SQLite and enable row dict access
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Create all tables on startup if they don't exist
def init_db():
    conn = get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                account_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                role            TEXT NOT NULL CHECK(role IN ('customer','merchant')),
                cert_id         INTEGER,
                create_time     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS products (
                product_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                merchant_id     INTEGER NOT NULL REFERENCES accounts(account_id),
                product_name    TEXT NOT NULL,
                price           REAL NOT NULL,
                description     TEXT,
                stock           INTEGER DEFAULT 0,
                create_time     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS orders (
                order_id            INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id         INTEGER NOT NULL REFERENCES accounts(account_id),
                product_id          INTEGER NOT NULL REFERENCES products(product_id),
                merchant_id         INTEGER NOT NULL REFERENCES accounts(account_id),
                quantity            INTEGER NOT NULL DEFAULT 1,
                total_amount        REAL NOT NULL,
                nonce               TEXT NOT NULL,
                order_digest        TEXT NOT NULL,
                customer_signature  TEXT,
                order_status        TEXT NOT NULL DEFAULT 'pending_payment',
                create_time         INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payments (
                payment_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id            INTEGER NOT NULL REFERENCES orders(order_id),
                payment_status      TEXT NOT NULL,
                gateway_signature   TEXT,
                payment_time        INTEGER
            );
        """)
        conn.commit()
    except Exception as e:
        print(f"[DB] init error: {e}")
    finally:
        conn.close()

init_db()

# ─── Part 2: Helper Functions ───

def _jsonify_amount(v: float):
    return int(v) if v == int(v) else v

# Generate a 4-character alphanumeric captcha code
def generate_captcha_code() -> str:
    chars = string.digits + string.ascii_letters
    return ''.join(random.choices(chars, k=4))

# Verify captcha from Redis; one-time use, case-sensitive
def verify_captcha(session_id: str, user_input: str) -> bool:
    key = f"captcha:{session_id}"
    stored = redis_client.get(key)
    if not stored:
        return False
    redis_client.delete(key)
    return stored == user_input

# Verify that an internal request originates from the payment gateway
# using its CA-issued certificate and a signature over the order_id
def verify_gateway_request(request: Request) -> bool:
    cert_id_str = request.headers.get("X-Gateway-Cert-Id")
    signature   = request.headers.get("X-Gateway-Signature")
    order_id    = request.path_params.get("order_id")
    if not cert_id_str or not signature or not order_id:
        return False
    try:
        cert = ca_get_cert(int(cert_id_str))
        if not cert or cert.get("role") != Role.GATEWAY:
            return False
        return verify_signature_with_pem(cert["public_key"], str(order_id), signature)
    except Exception:
        return False

# ─── Part 3: Schemas ───

class RegisterRequest(BaseModel):
    username: str
    password: str
    confirm_password: str
    role: str
    session_id: str
    captcha: str

class LoginRequest(BaseModel):
    username: str
    password: str
    role: str
    session_id: str
    captcha: str

class ProductCreate(BaseModel):
    product_name: str
    price: float
    description: Optional[str] = ""
    stock: Optional[int] = 0

class ProductUpdate(BaseModel):
    product_name: Optional[str] = None
    price: Optional[float] = None
    description: Optional[str] = None
    stock: Optional[int] = None

class OrderCreate(BaseModel):
    product_id: int
    quantity: int
    nonce: str
    customer_signature: str   # hex signature over order_digest
    customer_cert_id: int     # cert_id from CA
    session_id: str
    captcha: str

class PaymentSubmit(BaseModel):
    order_id: int
    encrypted_payment_info: str   # hex, RSA-OAEP encrypted with gateway pubkey
    customer_signature: str       # hex signature over payment digest
    customer_cert_id: int

class RevokeAndReissueRequest(BaseModel):
    password: str
    new_public_key_pem: str
    session_id: str
    captcha: str

# ─── Part 4: Static & Captcha ───

# Serve the frontend entry point
@app.get("/")
async def root():
    return FileResponse("frontend/index.html")

# Generate a captcha image and store the code in Redis with 5-minute TTL
@app.get("/auth/captcha")
def get_captcha(session_id: str):
    code = generate_captcha_code()
    redis_client.setex(f"captcha:{session_id}", 300, code)

    img  = Image.new('RGB', (160, 50), color="#e8e8e860")  # type: ignore
    draw = ImageDraw.Draw(img)
    colors = ['#e63946', '#2a9d8f', '#e76f51', '#457b9d', '#6a4c93', '#f4a261']
    x = 15
    for ch in code:
        draw.text((x, 8), ch, fill=random.choice(colors), font=font)  # type: ignore
        x += 32
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode()
    return {"image": f"data:image/png;base64,{b64}"}

# ─── Part 5: Authentication Routes ───

# Register a new account: validate captcha, role, password rules, username uniqueness
# On success, return a short-lived token so the frontend can immediately request a certificate
@app.post("/auth/register")
def register(req: RegisterRequest):
    if not verify_captcha(req.session_id, req.captcha):
        raise HTTPException(400, "Invalid or expired captcha")
    if req.role not in (Role.CUSTOMER, Role.MERCHANT):
        raise HTTPException(400, "Invalid role")
    if req.password != req.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    if len(req.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if len(req.username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")

    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO accounts (username, password_hash, role, create_time) VALUES (?,?,?,?)",
            (req.username, hash_password(req.password), req.role, int(time.time()))
        )
        conn.commit()
        account_id = cursor.lastrowid
        assert account_id is not None
        temp_token = create_token(account_id, req.username, req.role)
        return {"message": "Registration successful", "token": temp_token,
                "account_id": account_id, "username": req.username, "role": req.role}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username already exists")
    finally:
        conn.close()

# Log in with username and password; validate captcha before checking credentials
@app.post("/auth/login")
def login(req: LoginRequest):
    if not verify_captcha(req.session_id, req.captcha):
        raise HTTPException(400, "Invalid or expired captcha")
    if req.role not in (Role.CUSTOMER, Role.MERCHANT):
        raise HTTPException(400, "Invalid role")

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM accounts WHERE username=? AND role=?",
        (req.username, req.role)
    ).fetchone()
    conn.close()

    if not row or row["password_hash"] != hash_password(req.password):
        raise HTTPException(401, "Invalid credentials")

    token = create_token(row["account_id"], row["username"], row["role"])
    return {"token": token, "account_id": row["account_id"],
            "username": row["username"], "role": row["role"],
            "cert_id": row["cert_id"]}

# Return the current user's info decoded from JWT
@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return user

# Request a CA-signed certificate for the user's public key
# If a certificate already exists, fetch and return it instead of issuing a duplicate
@app.post("/auth/request-cert")
def request_cert(body: dict, user=Depends(get_current_user)):
    public_key_pem = body.get("public_key_pem")
    if not public_key_pem:
        raise HTTPException(400, "public_key_pem required")
    try:
        cert = ca_issue_cert(user["username"], user["role"], public_key_pem)
    except HTTPException as e:
        if "already exists" in str(e.detail):
            cert_resp = _httpx.get(
                f"{CA_URL}/ca/cert/subject/{user['username']}?role={user['role']}",
                timeout=5
            )
            if cert_resp.status_code != 200:
                raise HTTPException(400, "Could not retrieve existing certificate")
            cert = cert_resp.json()
        else:
            raise

    conn = get_db()
    conn.execute("UPDATE accounts SET cert_id=? WHERE account_id=?",
                 (cert["cert_id"], user["account_id"]))
    conn.commit()
    conn.close()
    return cert

# Return the certificate validity status and days remaining for the current user
@app.get("/auth/cert-status")
def cert_status(user=Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT cert_id FROM accounts WHERE account_id=?",
                       (user["account_id"],)).fetchone()
    conn.close()
    if not row or not row["cert_id"]:
        return {"status": "no_cert"}

    cert = ca_get_cert(row["cert_id"])
    if not cert:
        return {"status": "ca_unreachable"}

    days_left = (cert["expire_date"] - int(time.time())) // 86400
    if days_left < 0:
        return {"status": "expired", "days_left": 0}
    elif days_left <= 1:
        return {"status": "expiring_almost", "days_left": days_left}
    elif days_left < 30:
        return {"status": "expiring_soon", "days_left": days_left}
    else:
        return {"status": "valid", "days_left": days_left}

# Challenge-response login step 1: generate a 60-second challenge for the user
@app.post("/auth/challenge")
def request_challenge(body: dict):
    username = body.get("username")
    role     = body.get("role")
    if not username or not role:
        raise HTTPException(400, "Username and role are required")
    
    conn = get_db()
    row = conn.execute(
        "SELECT cert_id FROM accounts WHERE username=? AND role=?",
        (username, role)
    ).fetchone()
    conn.close()
    if not row or not row["cert_id"]:
        raise HTTPException(404, "User not found or no certificate")
    challenge = create_challenge(username, role)
    return {"challenge": challenge}

# Challenge-response login step 2: verify the signed challenge and issue a JWT
@app.post("/auth/login-with-key")
def login_with_key(body: dict):
    username      = body.get("username")
    role          = body.get("role")
    signature_hex = body.get("signature")
    session_id    = body.get("session_id")
    captcha       = body.get("captcha")

    if not username or not role or not signature_hex:
        raise HTTPException(400, "username, role and signature are required")
    if not session_id or not captcha:
        raise HTTPException(400, "Captcha is required")
    if not verify_captcha(session_id, captcha):
        raise HTTPException(400, "Invalid or expired captcha")

    challenge = pop_challenge(username, role)
    if not challenge:
        raise HTTPException(400, "Challenge expired or not found")

    conn = get_db()
    row = conn.execute(
        "SELECT account_id, cert_id FROM accounts WHERE username=? AND role=?",
        (username, role)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")

    cert = ca_get_cert(row["cert_id"])
    if not cert:
        raise HTTPException(400, "Could not fetch certificate")

    valid, reason = ca_verify_cert(cert)
    if not valid:
        raise HTTPException(401, f"Certificate invalid: {reason}")

    if not verify_signature_with_pem(cert["public_key"], challenge, signature_hex):
        raise HTTPException(401, "Signature verification failed")

    token = create_token(row["account_id"], username, role)
    return {"token": token, "account_id": row["account_id"],
            "username": username, "role": role}

# Revoke the current certificate and issue a new one after verifying password and captcha
@app.post("/auth/revoke-and-reissue")
def revoke_and_reissue(req: RevokeAndReissueRequest, user=Depends(get_current_user)):
    if not verify_captcha(req.session_id, req.captcha):
        raise HTTPException(400, "Invalid or expired captcha")

    conn = get_db()
    row = conn.execute("SELECT * FROM accounts WHERE account_id=?",
                       (user["account_id"],)).fetchone()
    if not row or row["password_hash"] != hash_password(req.password):
        conn.close()
        raise HTTPException(400, "Incorrect password")

    old_cert_id = row["cert_id"]
    if old_cert_id:
        ca_revoke_cert(old_cert_id, "User requested revocation and re-issuance")

    new_cert = ca_issue_cert(user["username"], user["role"], req.new_public_key_pem)

    conn.execute("UPDATE accounts SET cert_id=? WHERE account_id=?",
                 (new_cert["cert_id"], user["account_id"]))
    conn.commit()
    conn.close()
    return new_cert

# ─── Part 6: Product Routes ───

# Create a new product listing for the authenticated merchant
@app.post("/products", status_code=201)
def create_product(req: ProductCreate, user=Depends(require_role(Role.MERCHANT))):
    if req.price <= 0:
        raise HTTPException(400, "Price must be positive")
    if not req.product_name.strip():
        raise HTTPException(400, "Product name cannot be empty")

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO products (merchant_id, product_name, price, description, stock, create_time) "
        "VALUES (?,?,?,?,?,?)",
        (user["account_id"], req.product_name.strip(), req.price,
         req.description, req.stock, int(time.time()))
    )
    conn.commit()
    product_id = cursor.lastrowid
    conn.close()
    return {"message": "Product created", "product_id": product_id}

# List all products, optionally filtered by merchant_id
@app.get("/products")
def list_products(merchant_id: Optional[int] = None):
    conn = get_db()
    if merchant_id:
        rows = conn.execute(
            """SELECT p.*, a.username as merchant_name
               FROM products p JOIN accounts a ON p.merchant_id=a.account_id
               WHERE p.merchant_id=? ORDER BY p.create_time DESC""",
            (merchant_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT p.*, a.username as merchant_name
               FROM products p JOIN accounts a ON p.merchant_id=a.account_id
               ORDER BY p.create_time DESC"""
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Fetch a single product by ID
@app.get("/products/{product_id}")
def get_product(product_id: int):
    conn = get_db()
    row = conn.execute(
        """SELECT p.*, a.username as merchant_name
           FROM products p JOIN accounts a ON p.merchant_id=a.account_id
           WHERE p.product_id=?""",
        (product_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Product not found")
    return dict(row)

# Update product fields; only the owning merchant may modify a product
@app.put("/products/{product_id}")
def update_product(product_id: int, req: ProductUpdate,
                   user=Depends(require_role(Role.MERCHANT))):
    conn = get_db()
    row = conn.execute("SELECT * FROM products WHERE product_id=?", (product_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Product not found")
    if row["merchant_id"] != user["account_id"]:
        raise HTTPException(403, "Not your product")

    fields, values = [], []
    if req.product_name is not None:
        fields.append("product_name=?"); values.append(req.product_name.strip())
    if req.price is not None:
        if req.price <= 0:
            raise HTTPException(400, "Price must be positive")
        fields.append("price=?"); values.append(req.price)
    if req.description is not None:
        fields.append("description=?"); values.append(req.description)
    if req.stock is not None:
        fields.append("stock=?"); values.append(req.stock)

    if fields:
        values.append(product_id)
        conn.execute(f"UPDATE products SET {','.join(fields)} WHERE product_id=?", values)
        conn.commit()
    conn.close()
    return {"message": "Product updated"}

# Delete a product; only the owning merchant may delete it
@app.delete("/products/{product_id}")
def delete_product(product_id: int, user=Depends(require_role(Role.MERCHANT))):
    conn = get_db()
    row = conn.execute("SELECT * FROM products WHERE product_id=?", (product_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Product not found")
    if row["merchant_id"] != user["account_id"]:
        raise HTTPException(403, "Not your product")
    conn.execute("DELETE FROM products WHERE product_id=?", (product_id,))
    conn.commit()
    conn.close()
    return {"message": "Product deleted"}

# ─── Part 7: Merchant Stats & Orders ───

# Return total product count and total stock for the authenticated merchant
@app.get("/merchant/stats")
def merchant_stats(user=Depends(require_role(Role.MERCHANT))):
    conn = get_db()
    stats = conn.execute(
        "SELECT COUNT(*) as total_products, COALESCE(SUM(stock),0) as total_stock "
        "FROM products WHERE merchant_id=?",
        (user["account_id"],)
    ).fetchone()
    conn.close()
    return dict(stats)

# Return all orders placed for the authenticated merchant's products
@app.get("/merchant/orders")
def merchant_orders(user=Depends(require_role(Role.MERCHANT))):
    conn = get_db()
    rows = conn.execute(
        "SELECT o.*, p.product_name, a.username as customer_name "
        "FROM orders o "
        "JOIN products p ON o.product_id=p.product_id "
        "JOIN accounts a ON o.customer_id=a.account_id "
        "WHERE o.merchant_id=? ORDER BY o.create_time DESC",
        (user["account_id"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ─── Part 8: Order Routes ───

# Create a new order: verify captcha, certificate, stock, digital signature, and nonce uniqueness
@app.post("/orders")
def create_order(req: OrderCreate, user=Depends(require_role(Role.CUSTOMER))):
    if not verify_captcha(req.session_id, req.captcha):
        raise HTTPException(400, "Invalid or expired captcha")

    cert = ca_get_cert(req.customer_cert_id)
    if not cert:
        raise HTTPException(400, "Could not fetch customer certificate")
    valid, reason = ca_verify_cert(cert)
    if not valid:
        raise HTTPException(400, f"Certificate invalid: {reason}")

    conn = get_db()
    product = conn.execute("SELECT * FROM products WHERE product_id=?",
                           (req.product_id,)).fetchone()
    if not product:
        conn.close()
        raise HTTPException(404, "Product not found")
    if product["stock"] < req.quantity:
        conn.close()
        raise HTTPException(400, "Insufficient stock")

    total_amount = round(product["price"] * req.quantity, 2)
    merchant_id  = product["merchant_id"]

    # Build canonical order digest and verify customer's RSA signature
    order_digest = json.dumps({
        "nonce":        req.nonce,
        "product_id":   req.product_id,
        "quantity":     req.quantity,
        "total_amount": _jsonify_amount(total_amount),
    }, sort_keys=True, separators=(',', ':'))
    #print(order_digest)

    if not verify_signature_with_pem(cert["public_key"], order_digest, req.customer_signature):
        conn.close()
        raise HTTPException(400, "Customer signature verification failed")

    # Reject duplicate nonces to prevent replay attacks
    if conn.execute("SELECT order_id FROM orders WHERE nonce=?", (req.nonce,)).fetchone():
        conn.close()
        raise HTTPException(400, "Duplicate nonce — possible replay attack")

    cursor = conn.execute(
        "INSERT INTO orders (customer_id, product_id, merchant_id, quantity, "
        "total_amount, nonce, order_digest, customer_signature, create_time) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (user["account_id"], req.product_id, merchant_id, req.quantity,
         total_amount, req.nonce, order_digest, req.customer_signature, int(time.time()))
    )
    conn.execute("UPDATE products SET stock = stock - ? WHERE product_id = ?",
                 (req.quantity, req.product_id))
    conn.commit()
    order_id = cursor.lastrowid
    conn.close()

    return {"order_id": order_id, "total_amount": total_amount,
            "order_status": OrderStatus.PENDING_PAYMENT, "order_digest": order_digest}

# Fetch a single order; customers see only their own, merchants see only their incoming orders
@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Order not found")
    order = dict(row)
    if user["role"] == Role.CUSTOMER and order["customer_id"] != user["account_id"]:
        raise HTTPException(403, "Access denied")
    if user["role"] == Role.MERCHANT and order["merchant_id"] != user["account_id"]:
        raise HTTPException(403, "Access denied")
    return order

# List all orders for the current user
@app.get("/orders")
def list_orders(user=Depends(get_current_user)):
    conn = get_db()
    if user["role"] == Role.CUSTOMER:
        rows = conn.execute(
            """SELECT o.*, p.product_name
               FROM orders o JOIN products p ON o.product_id=p.product_id
               WHERE o.customer_id=? ORDER BY o.create_time DESC""",
            (user["account_id"],)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM orders WHERE merchant_id=? ORDER BY create_time DESC",
            (user["account_id"],)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Internal endpoint for the gateway to query order details; requires gateway PKI signature
@app.get("/internal/orders/{order_id}")
def get_order_internal(order_id: int, request: Request):
    if not verify_gateway_request(request):
        raise HTTPException(403, "Invalid or missing gateway signature")
    conn = get_db()
    row = conn.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Order not found")
    return dict(row)

# ─── Part 9: Payment Routes ───

# Submit payment: verify order ownership, forward to gateway, verify gateway signature, mark paid
@app.post("/payments/submit")
def submit_payment(req: PaymentSubmit, user=Depends(require_role(Role.CUSTOMER))):
    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE order_id=?",
                         (req.order_id,)).fetchone()
    if not order or order["customer_id"] != user["account_id"]:
        conn.close()
        raise HTTPException(403, "Order not found or access denied")
    if order["order_status"] != OrderStatus.PENDING_PAYMENT:
        conn.close()
        raise HTTPException(400, f"Order status is '{order['order_status']}', cannot pay")
    conn.close()

    cert = ca_get_cert(req.customer_cert_id)
    if not cert:
        raise HTTPException(400, "Could not fetch customer certificate")

    result = gateway_process_payment({
        "order_id":               req.order_id,
        "encrypted_payment_info": req.encrypted_payment_info,
        "customer_cert":          cert,
        "customer_signature":     req.customer_signature,
    })

    # Verify gateway signature on the payment result to confirm authenticity
    gw_cert = gateway_get_cert()
    if not verify_signature_with_pem(gw_cert["public_key"],
                                     result["result_payload"],
                                     result["gateway_signature"]):
        raise HTTPException(400, "Gateway signature verification failed")

    conn = get_db()
    conn.execute("UPDATE orders SET order_status=? WHERE order_id=?",
                 (OrderStatus.PAID, req.order_id))
    conn.execute(
        "INSERT INTO payments (order_id, payment_status, gateway_signature, payment_time) "
        "VALUES (?,?,?,?)",
        (req.order_id, result["payment_status"],
         result["gateway_signature"], result["payment_time"])
    )
    conn.commit()
    conn.close()

    return {"message": "Payment successful", "payment_id": result["payment_id"],
            "order_id": req.order_id, "payment_status": result["payment_status"],
            "gateway_signature_verified": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
    