# service_client.py
import httpx
from fastapi import HTTPException
from typing import Dict, Tuple, Optional

CA_URL      = "http://localhost:8101"
GATEWAY_URL = "http://localhost:8102"

def ca_get_cert(cert_id: int) -> Optional[Dict]:
    try:
        resp = httpx.get(f"{CA_URL}/ca/cert/{cert_id}", timeout=5)
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None

def ca_verify_cert(cert: dict) -> Tuple[bool, str]:
    try:
        resp = httpx.post(f"{CA_URL}/ca/verify-cert", json=cert, timeout=5)
        result = resp.json()
        return result.get("valid", False), result.get("reason", "")
    except Exception:
        return False, "CA server unreachable"

def ca_issue_cert(subject: str, role: str, public_key_pem: str) -> dict:
    try:
        resp = httpx.post(f"{CA_URL}/ca/issue-cert", json={
            "subject": subject, "role": role, "public_key_pem": public_key_pem
        }, timeout=10)
        if resp.status_code != 200:
            raise HTTPException(400, f"CA rejected: {resp.json().get('detail')}")
        return resp.json()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "CA server unreachable")

def ca_revoke_cert(cert_id: int, reason: str) -> None:
    try:
        httpx.post(f"{CA_URL}/ca/revoke",
                   json={"cert_id": cert_id, "reason": reason}, timeout=5)
    except Exception:
        pass  # revocation failure is logged but not fatal

def gateway_get_cert() -> dict:
    try:
        resp = httpx.get(f"{GATEWAY_URL}/gateway/cert", timeout=5)
        return resp.json()
    except Exception:
        raise HTTPException(503, "Gateway unreachable")

def gateway_process_payment(payload: dict) -> dict:
    try:
        resp = httpx.post(f"{GATEWAY_URL}/gateway/process-payment",
                          json=payload, timeout=15)
        result = resp.json()
        if resp.status_code != 200:
            raise HTTPException(400, result.get("detail", "Payment failed"))
        return result
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Payment gateway unreachable")