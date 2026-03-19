"""
Payment Gateway Server  —  port 8102

Responsibilities:
- Generate its own RSA key pair on startup and register with CA
- Receive encrypted payment requests from customers
- Decrypt payment info using its own private key
- Verify customer certificate and signature via CA
- Query order status from main server
- Process payment (simulated) and return signed result to merchant

Database: gateway.db (separate)
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3
import time
import json
import httpx

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from utils.crypto_utils import sign_data, verify_signature_with_pem, generate_rsa_keypair

def _jsonify_amount(v: float):
    return int(v) if v == int(v) else v

# ─── APP SETUP ───────────────────────────────────────────────────────────────

app = FastAPI(title="Payment Gateway Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH      = "./database/gateway.db"
CA_URL       = "http://localhost:8101"
MERCHANT_URL = "http://localhost:8100"
GATEWAY_NAME = "SecureShop-Gateway"
GATEWAY_PORT = 8102

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS gateway_keypair (
            id          INTEGER PRIMARY KEY CHECK(id = 1),
            private_key TEXT NOT NULL,
            public_key  TEXT NOT NULL,
            cert_id     INTEGER,
            created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payments (
            payment_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id         INTEGER NOT NULL,
            customer_subject TEXT NOT NULL,
            masked_card_info TEXT,
            payment_amount   REAL NOT NULL,
            payment_status   TEXT NOT NULL DEFAULT 'pending',
            gateway_signature TEXT,
            payment_time     INTEGER,
            fail_reason      TEXT
        );
    """)
    conn.commit()
    conn.close()

# ─── GATEWAY KEY MANAGEMENT ──────────────────────────────────────────────────

# Register with CA
def apply_cert(pub_pem):
    try:
        resp = httpx.post(f"{CA_URL}/ca/issue-cert", json={
            "subject": GATEWAY_NAME,
            "role": "gateway",
            "public_key_pem": pub_pem
        }, timeout=10)
        if resp.status_code == 200:
            cert_id = resp.json()["cert_id"]
            conn = get_db()
            conn.execute("UPDATE gateway_keypair SET cert_id=? WHERE id=1", (cert_id,))
            conn.commit()
            conn.close()
            print(f"[Gateway] Certificate issued, cert_id={cert_id}")
        else:
            print(f"[Gateway] CA registration failed: {resp.text}")
    except Exception as e:
        print(f"[Gateway] Could not reach CA: {e}")

def load_or_generate_gateway_keypair():
    """Load existing gateway key pair, or generate and register with CA."""
    conn = get_db()
    row = conn.execute("SELECT * FROM gateway_keypair WHERE id=1").fetchone()

    # already generated key pair
    if row:
        private_key = serialization.load_pem_private_key(
            row["private_key"].encode(), password=None, backend=default_backend()
        )
        conn.close()
        
        # not acquire certificate from CA
        if not row["cert_id"]:
            pub_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            print("[Gateway] Key pair exists but no certificate — registering with CA...")
            apply_cert(pub_pem)
        
        return private_key

    # generate key pair for gateway
    private_key, priv_pem, pub_pem = generate_rsa_keypair()

    conn.execute(
        "INSERT INTO gateway_keypair (id, private_key, public_key, created_at) VALUES (1,?,?,?)",
        (priv_pem, pub_pem, int(time.time()))
    )
    conn.commit()
    conn.close()
    print("[Gateway] New RSA key pair generated.")

    apply_cert(pub_pem)

    return private_key

def get_gateway_public_key_pem() -> str:
    conn = get_db()
    row = conn.execute("SELECT public_key FROM gateway_keypair WHERE id=1").fetchone()
    conn.close()
    return row["public_key"] if row else None # type: ignore

def get_gateway_cert_id() -> Optional[int]:
    conn = get_db()
    row = conn.execute("SELECT cert_id FROM gateway_keypair WHERE id=1").fetchone()
    conn.close()
    return row["cert_id"] if row else None

# ─── CRYPTO HELPERS ──────────────────────────────────────────────────────────

def decrypt_with_private_key(private_key, ciphertext_hex: str) -> str:
    """Decrypt RSA-OAEP encrypted data using gateway private key."""
    plaintext = private_key.decrypt(
        bytes.fromhex(ciphertext_hex),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# ─── STARTUP ─────────────────────────────────────────────────────────────────

init_db()
GATEWAY_PRIVATE_KEY = load_or_generate_gateway_keypair()

# ─── SCHEMAS ─────────────────────────────────────────────────────────────────

class PaymentRequest(BaseModel):
    order_id: int
    encrypted_payment_info: str   # RSA-OAEP encrypted JSON, hex-encoded
    customer_cert: dict           # customer's full certificate object
    customer_signature: str       # customer's signature over order digest

class PaymentStatusRequest(BaseModel):
    order_id: int

# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.get("/gateway/public-key")
def gateway_public_key():
    """Return the gateway's RSA public key and certificate ID."""
    pub = get_gateway_public_key_pem()
    cert_id = get_gateway_cert_id()
    if not pub:
        raise HTTPException(500, "Gateway key not initialized")
    return {"public_key": pub, "cert_id": cert_id}

@app.get("/gateway/cert")
def gateway_cert():
    """Return the gateway's full certificate (fetched from CA)."""
    cert_id = get_gateway_cert_id()
    if not cert_id:
        raise HTTPException(500, "Gateway has no certificate yet")
    try:
        resp = httpx.get(f"{CA_URL}/ca/cert/{cert_id}", timeout=5)
        return resp.json()
    except Exception:
        raise HTTPException(503, "CA server unreachable")

@app.post("/gateway/process-payment")
def process_payment(req: PaymentRequest):
    """
    Full payment processing flow:
    1. Verify customer certificate with CA
    2. Decrypt payment info
    3. Verify customer signature over order digest
    4. Query order from merchant server
    5. Simulate payment
    6. Sign result and return
    """

    # Step 1: Verify customer certificate
    try:
        ca_resp = httpx.post(f"{CA_URL}/ca/verify-cert", json=req.customer_cert, timeout=5)
        cert_check = ca_resp.json()
    except Exception:
        raise HTTPException(503, "CA server unreachable")

    if not cert_check.get("valid"):
        raise HTTPException(400, f"Invalid customer certificate: {cert_check.get('reason')}")

    # Step 2: Decrypt payment info
    try:
        payment_json = decrypt_with_private_key(GATEWAY_PRIVATE_KEY, req.encrypted_payment_info)
        payment_info = json.loads(payment_json)
    except Exception as e:
        raise HTTPException(400, f"Failed to decrypt payment info: {str(e)}")

    # Step 3: Query order from merchant server to confirm amount matches
    try:
        # Sign the order_id with gateway private key for inter-service authentication
        gw_signature = sign_data(GATEWAY_PRIVATE_KEY, str(req.order_id))
        gw_cert_id   = get_gateway_cert_id()
        
        order_resp = httpx.get(
            f"{MERCHANT_URL}/internal/orders/{req.order_id}",
            headers={
                "X-Gateway-Cert-Id":   str(gw_cert_id),
                "X-Gateway-Signature": gw_signature
            },
            timeout=5
        )
        if order_resp.status_code != 200:
            raise HTTPException(400, "Order not found on merchant server")
        order = order_resp.json()
    
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Merchant server unreachable")
    
    # Step 4: Verify customer signature over order_id
    order_digest = json.dumps({
        "order_id": req.order_id,
        "amount": _jsonify_amount(float(order["total_amount"])),
        "nonce": order["nonce"]
    }, separators=(',', ':'), sort_keys=True)
    sig_valid = verify_signature_with_pem(
        req.customer_cert["public_key"],
        order_digest,
        req.customer_signature
    )
    if not sig_valid:
        raise HTTPException(400, "Customer signature verification failed")

    # Step 5: Verify payment amount matches order total
    if abs(float(payment_info.get("amount", 0)) - float(order["total_amount"])) > 0.01:
        raise HTTPException(400, "Payment amount does not match order total")

    # Step 5: Simulate payment processing
    masked_card = "****" + str(payment_info.get("card_number", ""))[-4:]
    payment_time = int(time.time())
    payment_status = "success"  # Simulated — always succeeds

    # Step 6: Sign the payment result
    result_payload = json.dumps({
        "order_id": req.order_id,
        "payment_status": payment_status,
        "payment_time": payment_time,
        "gateway": GATEWAY_NAME
    }, sort_keys=True)
    gateway_signature = sign_data(GATEWAY_PRIVATE_KEY, result_payload)

    # Store payment record in gateway DB
    conn = get_db()
    cursor = conn.execute(
        """INSERT INTO payments
           (order_id, customer_subject, masked_card_info, payment_amount,
            payment_status, gateway_signature, payment_time)
           VALUES (?,?,?,?,?,?,?)""",
        (req.order_id, req.customer_cert["subject"], masked_card,
         order["total_amount"], payment_status, gateway_signature, payment_time)
    )
    conn.commit()
    payment_id = cursor.lastrowid
    conn.close()

    return {
        "payment_id": payment_id,
        "order_id": req.order_id,
        "payment_status": payment_status,
        "payment_time": payment_time,
        "gateway_signature": gateway_signature,
        "result_payload": result_payload  # merchant uses this to verify signature
    }

@app.get("/gateway/payments")
def list_payments():
    """List all payment records (admin/debug view)."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM payments ORDER BY payment_time DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

if __name__ == "__main__":
    import uvicorn
    print(f"[Gateway] Gateway is running at port {GATEWAY_PORT}!")
    uvicorn.run(app, host="0.0.0.0", port=GATEWAY_PORT)