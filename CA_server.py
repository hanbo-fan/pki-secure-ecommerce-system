"""
CA / PKI Server  —  port 8101

Responsibilities:
- Generate and store the CA's own RSA key pair on startup
- Issue signed certificates for merchants, customers, and the payment gateway
- Expose certificate lookup and CRL (certificate revocation list) endpoints
- Revoke certificates on request

Database: ca.db (separate from main ecommerce.db)
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3
import time
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from utils.crypto_utils import sign_data, verify_signature_with_pem, generate_rsa_keypair

# ─── Part 1: App Setup ───

app = FastAPI(title="CA / PKI Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "./database/ca.db"
CA_PORT = 8101

# ─── Part 2: Database ───

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ca_keypair (
            id           INTEGER PRIMARY KEY CHECK(id = 1),
            private_key  TEXT NOT NULL,
            public_key   TEXT NOT NULL,
            created_at   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS certificates (
            cert_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            subject             TEXT NOT NULL,
            role                TEXT NOT NULL,
            public_key          TEXT NOT NULL,
            serial_number       TEXT UNIQUE NOT NULL,
            issue_date          INTEGER NOT NULL,
            expire_date         INTEGER NOT NULL,
            signature_algorithm TEXT NOT NULL DEFAULT 'RSA-SHA256',
            key_usage           TEXT NOT NULL,
            ca_signature        TEXT NOT NULL,
            status              TEXT NOT NULL DEFAULT 'active'
        );

        CREATE TABLE IF NOT EXISTS crl (
            crl_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_id      INTEGER NOT NULL REFERENCES certificates(cert_id),
            revoke_reason TEXT NOT NULL,
            revoke_time  INTEGER NOT NULL
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ─── Part 3: CA Key Management ───

# Load existing CA key pair from DB, or generate a new one on first run
def load_or_generate_ca_keypair():
    conn = get_db()
    row = conn.execute("SELECT * FROM ca_keypair WHERE id=1").fetchone()

    # Find existing CA private key and return
    if row:
        private_key = serialization.load_pem_private_key(
            row["private_key"].encode(), password=None, backend=default_backend()
        )
        conn.close()
        return private_key

    # First run: generate CA RSA-2048 key pair
    private_key, priv_pem, pub_pem = generate_rsa_keypair()

    # Store private key and public key into DB
    conn.execute(
        "INSERT INTO ca_keypair (id, private_key, public_key, created_at) VALUES (1,?,?,?)",
        (priv_pem, pub_pem, int(time.time()))
    )
    conn.commit()
    conn.close()
    print("[CA] New CA key pair generated and stored.")
    return private_key

# Get CA public key from DB
def get_ca_public_key_pem() -> str:
    conn = get_db()
    row = conn.execute("SELECT public_key FROM ca_keypair WHERE id=1").fetchone()
    conn.close()
    return row["public_key"] if row else None # type: ignore

CA_PRIVATE_KEY = load_or_generate_ca_keypair()

# ─── Part 4: Crypto Helper Functions ───

# Build deterministic string representation of cert fields to be signed
def build_cert_payload(subject: str, role: str, public_key_pem: str,
                        serial: str, issue_date: int, expire_date: int) -> str:
    return json.dumps({
        "subject": subject,
        "role": role,
        "public_key": public_key_pem,
        "serial_number": serial,
        "issue_date": issue_date,
        "expire_date": expire_date,
        "signature_algorithm": "RSA-SHA256",
        "key_usage": "digitalSignature, keyEncipherment"
    }, sort_keys = True)

# ─── Schemes ───

class CertRequest(BaseModel):
    subject: str           # username or service name
    role: str              # 'customer', 'merchant', 'gateway'
    public_key_pem: str    # applicant's RSA public key in PEM format

class RevokeRequest(BaseModel):
    cert_id: int
    reason: str

# ─── Part 5: Routes ───

# Return the CA's own public key (used by all parties to verify signatures)
@app.get("/ca/public-key")
def ca_public_key():
    pem = get_ca_public_key_pem()
    if not pem:
        raise HTTPException(500, "CA key not initialized")
    return {"ca_public_key": pem}

@app.post("/ca/issue-cert")
def issue_cert(req: CertRequest):
    """
    Issue a signed certificate for the given subject.
    The CA signs a payload of the cert fields using its private key.
    """
    if req.role not in ("customer", "merchant", "gateway"):
        raise HTTPException(400, "Invalid role")

    # Check for existing active cert for this subject+role
    conn = get_db()
    existing = conn.execute(
        "SELECT cert_id FROM certificates WHERE subject=? AND role=? AND status='active'",
        (req.subject, req.role)
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, f"Active certificate already exists for {req.subject}")

    import secrets
    serial = secrets.token_hex(16).upper()
    issue_date = int(time.time())
    expire_date = issue_date + 365 * 24 * 3600  # 1 year

    payload = build_cert_payload(
        req.subject, req.role, req.public_key_pem,
        serial, issue_date, expire_date
    )
    ca_signature = sign_data(CA_PRIVATE_KEY, payload)

    cursor = conn.execute(
        """INSERT INTO certificates
           (subject, role, public_key, serial_number, issue_date, expire_date,
            key_usage, ca_signature, status)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (req.subject, req.role, req.public_key_pem, serial,
         issue_date, expire_date,
         "digitalSignature,keyEncipherment", ca_signature, "active")
    )
    conn.commit()
    cert_id = cursor.lastrowid
    conn.close()

    return {
        "cert_id": cert_id,
        "subject": req.subject,
        "role": req.role,
        "public_key": req.public_key_pem,
        "serial_number": serial,
        "issue_date": issue_date,
        "expire_date": expire_date,
        "signature_algorithm": "RSA-SHA256",
        "key_usage": "digitalSignature,keyEncipherment",
        "ca_signature": ca_signature,
        "status": "active"
    }

@app.get("/ca/cert/subject/{subject}")
def get_cert_by_subject(subject: str, role: Optional[str] = None):
    """Fetch the active certificate for a given subject (and optional role)."""
    conn = get_db()
    if role:
        row = conn.execute(
            "SELECT * FROM certificates WHERE subject=? AND role=? AND status='active'",
            (subject, role)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM certificates WHERE subject=? AND status='active'",
            (subject,)
        ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "No active certificate found")
    return dict(row)

# Fetch a certificate by cert_ID
@app.get("/ca/cert/{cert_id}")
def get_cert(cert_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM certificates WHERE cert_id=?", (cert_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Certificate not found")
    return dict(row)

# Verify that a certificate was genuinely issued by this CA
@app.post("/ca/verify-cert")
def verify_cert(cert: dict):
    try:
        # Check expiry
        if int(time.time()) > cert["expire_date"]:
            return {"valid": False, "reason": "Certificate expired"}

        # Check revocation
        conn = get_db()
        row = conn.execute(
            "SELECT status FROM certificates WHERE serial_number=?",
            (cert["serial_number"],)
        ).fetchone()
        conn.close()
        if not row:
            return {"valid": False, "reason": "Certificate not found in registry"}
        if row["status"] == "revoked":
            return {"valid": False, "reason": "Certificate has been revoked"}

        # Verify CA signature - Reconstructs the signed payload and checks the CA signature
        payload = build_cert_payload(
            cert["subject"], cert["role"], cert["public_key"],
            cert["serial_number"], cert["issue_date"], cert["expire_date"]
        )
        ca_pub_pem = get_ca_public_key_pem()
        ok = verify_signature_with_pem(ca_pub_pem, payload, cert["ca_signature"])
        if not ok:
            return {"valid": False, "reason": "Invalid CA signature"}

        return {"valid": True, "reason": "Certificate is valid"}
    except Exception as e:
        return {"valid": False, "reason": str(e)}

# Revoke a certificate and add it to the CRL
@app.post("/ca/revoke")
def revoke_cert(req: RevokeRequest):
    conn = get_db()
    row = conn.execute("SELECT * FROM certificates WHERE cert_id=?", (req.cert_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Certificate not found")
    if row["status"] == "revoked":
        conn.close()
        raise HTTPException(400, "Certificate already revoked")

    conn.execute("UPDATE certificates SET status='revoked' WHERE cert_id=?", (req.cert_id,))
    conn.execute(
        "INSERT INTO crl (cert_id, revoke_reason, revoke_time) VALUES (?,?,?)",
        (req.cert_id, req.reason, int(time.time()))
    )
    conn.commit()
    conn.close()
    return {"message": "Certificate revoked", "cert_id": req.cert_id}

# Return the full Certificate Revocation List
@app.get("/ca/crl")
def get_crl():
    conn = get_db()
    rows = conn.execute(
        """SELECT c.crl_id, c.cert_id, c.revoke_reason, c.revoke_time,
                  cert.subject, cert.serial_number
           FROM crl c JOIN certificates cert ON c.cert_id=cert.cert_id
           ORDER BY c.revoke_time DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# List all certificates, optionally filtered by role or status
@app.get("/ca/certs")
def list_certs(role: Optional[str] = None, status: Optional[str] = None):
    conn = get_db()
    query = "SELECT * FROM certificates WHERE 1=1"
    params = []
    if role:
        query += " AND role=?"; params.append(role)
    if status:
        query += " AND status=?"; params.append(status)
    query += " ORDER BY issue_date DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ─── Startup ───
if __name__ == "__main__":
    import uvicorn
    print(f"[CA] CA is running at port {CA_PORT}!")
    uvicorn.run(app, host="0.0.0.0", port=CA_PORT)