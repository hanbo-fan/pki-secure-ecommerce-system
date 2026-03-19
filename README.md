# SecureShop - PKI-Based Secure E-Commerce System with Digital Signatures and Payment Gateway

A full-stack experimental e-commerce system built to demonstrate real-world application of **Public Key Infrastructure (PKI)**, **RSA-2048 cryptography**, **digital signatures**, and **JWT-based authentication**. The payment flow is simulated; the cryptographic protocols are fully implemented.

> **Note:** This is an academic/experimental project. The payment module uses simulated processing - no real bank or card network is involved.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Roles & Responsibilities](#roles--responsibilities)
- [Module Flows](#module-flows)
  - [Registration & Certificate Issuance](#1-registration--certificate-issuance)
  - [Login (Password)](#2-login-password)
  - [Login (Private Key / Challenge-Response)](#3-login-private-key--challenge-response)
  - [Order Placement](#4-order-placement)
  - [Payment Processing](#5-payment-processing)
  - [Certificate Revocation & Re-issuance](#6-certificate-revocation--re-issuance)
- [Database Schema](#database-schema)
- [Security Design Notes](#security-design-notes)
- [Getting Started](#getting-started)
- [License](#license)

---

## Project Overview

SecureShop simulates the security infrastructure of a real e-commerce platform. The e-commerce scenario (products, orders, payments) exists as a vehicle to demonstrate these protocols in a realistic, multi-party context.

### Directory Structure

```
project/
├── main.py                 # Main server (port 8100)
├── CA_server.py            # CA / PKI server (port 8101)
├── gateway_server.py       # Payment gateway (port 8102)
├── utils/
│   ├── __init__.py
│   ├── crypto_utils.py     # RSA key generation, sign, verify
│   ├── auth_utils.py       # JWT, password hashing, challenge-response
│   ├── pki_client.py       # Inter-service HTTP calls (CA & gateway)
│   └── constants.py        # Role, OrderStatus, CertStatus
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── database/               # SQLite databases (auto-created on first run)
│   ├── ecommerce.db
│   ├── ca.db
│   └── gateway.db
├── .env.example            # Template committed to version control
└── .gitignore
```

**Core security mechanisms implemented:**

- **PKI**: A self-hosted Certificate Authority (CA) issues, stores, and revokes X.509-style certificates for all participants - customers, merchants, and the payment gateway.
- **RSA-2048**: Used for digital signatures (order integrity) and asymmetric encryption (payment info confidentiality via RSA-OAEP).
- **Browser-side key generation**: RSA key pairs are generated locally in the browser via the Web Crypto API. The private key never leaves the browser.
- **JWT(JSON Web Token)**: Stateless session tokens for API authentication, with role-based access control.
- **Inter-service authentication**: The payment gateway authenticates itself to the main server using its CA-issued certificate and a PKI signature - no shared API keys.
- **Anti-replay**: UUID nonces on orders, one-time CAPTCHA consumption, and 60-second challenge expiry on key-based login.
- **Payment signature binding**: The customer's payment signature covers `order_id`, `amount`, and `nonce` - preventing signature reuse across different payments.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend (Main) | Python · FastAPI · SQLite · Redis |
| CA Server | Python · FastAPI · SQLite · `cryptography` |
| Payment Gateway | Python · FastAPI · SQLite · `cryptography` |
| Frontend | Vanilla HTML / CSS / JavaScript · Web Crypto API · Luhn |
| Crypto | RSA-2048 · PKCS1v15 signatures · RSA-OAEP encryption · SHA-256 |
| Auth | JWT (HS256) · CAPTCHA · Challenge-Response |
| Config | `python-dotenv` for environment variable management |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Browser                          │
│   HTML + CSS + JS  ·  Web Crypto API (key generation)   │
└───────────┬──────────────────────────────┬──────────────┘
            │ HTTP :8100                   │ HTTP :8102
            ▼                              ▼
┌───────────────────────┐     ┌─────────────────────────┐
│   Main Server         │     │   Payment Gateway       │
│   (main.py)           │────▶│   (gateway_server.py)   │
│   port 8100           │     │   port 8102             │
│                       │     │                         │
│   - Auth              │     │  Decrypt payment info   │
│   - Products          │     │  Verify customer cert   │
│   - Orders            │     │  Sign payment result    │            
└───────────┬───────────┘     └────────────┬────────────┘
            │ HTTP :8101                   │ HTTP :8101
            └──────────────┬───────────────┘
                           ▼
              ┌────────────────────────┐
              │   CA / PKI Server      │
              │   (CA_server.py)       │
              │   port 8101            │
              │                        │
              │  Issue certificates    │
              │  Verify signatures     │
              │  Revoke / CRL          │
              └────────────────────────┘
```

All three services run independently. The browser communicates directly with the Main Server and the Gateway. Both the Main Server and the Gateway call the CA for all certificate operations.

---

## Roles & Responsibilities

### Customer
- Registers an account; an RSA-2048 key pair is generated **locally in the browser** via the Web Crypto API - **the private key never reaches the server**.
- Obtains a CA-signed certificate binding their public key to their identity.
- Logs in via password or private key challenge-response (CAPTCHA-protected).
- Signs order digests with their private key to prove intent and ensure non-repudiation.
- Encrypts payment info (card number + amount) with the gateway's RSA public key using RSA-OAEP before submission, ensuring end-to-end confidentiality.

### Merchant
- Registers similarly and receives a CA-signed certificate.
- Manages product listings (create, update, stock control).
- Views incoming orders after payment has been verified.

### Payment Gateway (`SecureShop-Gateway`)
- Generates its own RSA-2048 key pair on first startup and registers with the CA.
- Exposes its public key so customers can encrypt payment info end-to-end.
- Authenticates itself to the main server on every internal request using its CA certificate and a PKI-based signature (no shared API key).
- Decrypts payment info using its own private key.
- Verifies the customer's certificate (via CA) and their payment signature before processing.
- Cross-checks the payment amount against the order record on the Main Server to prevent tampering.
- Signs the payment result with its own private key; the Main Server verifies this signature before marking an order as paid.

### CA / PKI Server
- Generates and persists its own RSA-2048 key pair on first startup.
- Issues signed certificates (1-year validity) for customers, merchants, and the gateway.
- Verifies certificates on request: checks expiry, revocation status, and CA signature integrity.
- Maintains a Certificate Revocation List (CRL).
- Provides certificate lookup by `cert_id` or `subject` name.

---

## Module Flows

### 1. Registration & Certificate Issuance

```
Browser                          Main Server (:8100)        CA (:8101)
   │                                    │                         │
   │  [generate RSA-2048 key pair       │                         │
   │   locally via Web Crypto API]      │                         │
   │  [private key → localStorage       │                         │
   │   + downloaded as .pem]            │                         │
   │                                    │                         │
   │── POST /auth/register ────────────▶│                        │
   │   {username, password,             │ verify CAPTCHA          │
   │    role, captcha}                  │ insert account          │
   │◀─ {token, account_id} ────────────│                         │
   │                                    │                         │
   │── POST /auth/request-cert ────────▶│── POST /ca/issue-cert ▶│
   │   {public_key_pem}                 │                         │ sign cert payload
   │                                    │                         │ with CA private key
   │                                    │◀─ {cert_id, signature}  │
   │◀─ full certificate ───────────────│ store cert_id in DB      │
```

### 2. Login (Password)

```
Browser                      Main Server (:8100)
   │                                │
   │── POST /auth/login ───────────▶│
   │   {username, password,         │ verify CAPTCHA (Redis, one-time)
   │    role, session_id, captcha}  │ verify password hash (SHA-256)
   │◀─ {token, role} ──────────────│ return JWT (24h expiry)
```

### 3. Login (Private Key / Challenge-Response)

```
Browser                      Main Server (:8100)          CA (:8101)
   │                                │                          │
   │── POST /auth/challenge ───────▶│                         │
   │   {username, role}             │ generate 64-char hex     │
   │◀─ {challenge} ────────────────│ store in memory (60s TTL)│
   │                                │                          │
   │  [sign challenge with          │                          │
   │   private key via              │                          │
   │   Web Crypto API]              │                          │
   │                                │                          │
   │── POST /auth/login-with-key ──▶│                          │
   │   {username, role,             │ verify CAPTCHA           │
   │    signature, captcha}         │── GET /ca/cert/{id} ────▶│
   │                               │◀─ certificate ───────────│
   │                                │ verify RSA signature     │
   │                                │ over challenge string    │
   │◀─ {token} ────────────────────│ return JWT                │
```

### 4. Order Placement

```
Browser                     Main Server (:8100)            CA (:8101)
   │                               │                           │
   │  [build order digest]         │                           │
   │  digest = JSON({product_id,   │                           │
   │    quantity, total, nonce})   │                           │
   │  [sign digest with            │                           │
   │   private key]                │                           │
   │                               │                           │
   │── POST /orders ───────────────▶│                         │
   │   {product_id, quantity,      │ verify CAPTCHA            │
   │    nonce, signature,          │── GET /ca/cert/{id} ────▶│
   │    customer_cert_id,          │◀─ certificate ───────────│
   │    session_id, captcha}       │── POST /ca/verify-cert ──▶│
   │                               │◀─ {valid: true} ───────── │
   │                               │ verify RSA signature      │
   │                               │ check nonce uniqueness    │
   │                               │  (anti-replay)            │
   │                               │ deduct stock              │
   │◀─ {order_id, total_amount} ───│ insert order              │
```

### 5. Payment Processing

```
Browser            Main Server (:8100)      Gateway (:8102)        CA (:8101)
   │                     │                       │                     │
   │  [fetch gateway     │                       │                     │
   │   public key]       │                       │                     │
   │────────────────────────────────────────────▶│                     │
   │◀─ {public_key} ─────────────────────────────│                     │
   │                     │                       │                     │
   │  [encrypt {card,    │                       │                     │
   │   amount} with      │                       │                     │
   │   RSA-OAEP]         │                       │                     │
   │  [sign {order_id,   │                       │                     │
   │   amount, nonce}    │                       │                     │
   │   with private key] │                       │                     │
   │                     │                       │                     │
   │── POST /payments/submit                     │                     │
   │   {order_id,        │ verify order owner    │                     │
   │   encrypted_payment,│                       │                     │
   │   signature,        │── POST /gateway/process-payment            │
   │   cert_id} ────────▶│   + X-Gateway-Sig ──▶│ verify gateway sig  │
   │                     │                       │── POST /ca/verify ──▶│
   │                     │                       │◀─ {valid} ───────────│
   │                     │                       │ decrypt payment info │
   │                     │                       │ verify customer sig  │
   │                     │                       │  over {order_id,     │
   │                     │                       │   amount, nonce}     │
   │                     │                       │ check amount vs order│
   │                     │                       │ sign result payload  │
   │                     │◀─ {gateway_sig, ──────│                     │
   │                     │   result_payload}     │                     │
   │                     │ verify gateway sig    │                     │
   │                     │ update order → 'paid' │                     │
   │◀─ {payment_status} ─│                       │                     │
```

### 6. Certificate Revocation & Re-issuance

```
Browser                     Main Server (:8100)          CA (:8101)
   │                               │                         │
   │  [generate new RSA-2048       │                         │
   │   key pair locally]           │                         │
   │                               │                         │
   │── POST /auth/revoke-and- ─────▶│                         │
   │   reissue                     │ verify CAPTCHA           │
   │   {password,                  │ verify password hash     │
   │    new_public_key_pem}        │                         │
   │                               │── POST /ca/revoke ──────▶│
   │                               │   {old_cert_id}          │ mark revoked
   │                               │                          │ add to CRL
   │                               │── POST /ca/issue-cert ──▶│
   │                               │   {new_public_key_pem}   │ sign new cert
   │                               │◀─ new certificate ───────│
   │                               │ update cert_id in DB     │
   │◀─ new certificate ────────────│                         │
   │  [new private key             │                         │
   │   downloaded as .pem]         │                         │
```

---

## Database Schema

### `ecommerce.db` — Main Server

| Table | Key Columns |
|---|---|
| `accounts` | `account_id`, `username`, `password_hash` (SHA-256), `role`, `cert_id`, `create_time` |
| `products` | `product_id`, `merchant_id`, `product_name`, `price`, `stock` |
| `orders` | `order_id`, `customer_id`, `product_id`, `quantity`, `total_amount`, `nonce`, `order_digest`, `customer_signature`, `order_status` |
| `payments` | `payment_id`, `order_id`, `payment_status`, `gateway_signature`, `payment_time` |

### `ca.db` — CA Server

| Table | Key Columns |
|---|---|
| `ca_keypair` | `id=1` (singleton), `private_key` (PEM), `public_key` (PEM) |
| `certificates` | `cert_id`, `subject`, `role`, `public_key`, `serial_number`, `issue_date`, `expire_date`, `ca_signature`, `status` |
| `crl` | `crl_id`, `cert_id`, `revoke_reason`, `revoke_time` |

### `gateway.db` — Gateway Server

| Table | Key Columns |
|---|---|
| `gateway_keypair` | `id=1` (singleton), `private_key`, `public_key`, `cert_id` |
| `payments` | `payment_id`, `order_id`, `customer_subject`, `masked_card_info` (last 4 digits only), `payment_amount`, `payment_status`, `gateway_signature` |

> The gateway stores only the **last 4 digits** of the card number. Full card numbers are never persisted, consistent with PCI DSS principles.

### Redis — CAPTCHA Store

CAPTCHA codes are stored as `captcha:{session_id}` with a 5-minute TTL and deleted immediately after first use (one-time consumption).

---

## Security Design Notes

| Mechanism | Implementation |
|---|---|
| RSA key size | 2048-bit, `public_exponent=65537` |
| Key generation | Browser-side via Web Crypto API — private key never transmitted to server |
| Signature scheme | PKCS1v15 + SHA-256 |
| Encryption scheme | RSA-OAEP + SHA-256 (payment info) |
| Payment signature | Covers `order_id` + `amount` + `nonce` — prevents cross-payment signature reuse |
| Inter-service auth | Gateway signs each internal request with its CA-issued private key; main server verifies via CA |
| Password storage | SHA-256 hash (no salt — demo only; production should use bcrypt or Argon2) |
| JWT | HS256, 24-hour expiry, secret loaded from environment variable |
| CAPTCHA | 4-char alphanumeric, case-sensitive, Redis-backed, one-time use, 5-min TTL |
| Anti-replay (orders) | UUID nonce stored per order; duplicate nonces rejected |
| Anti-replay (key login) | Challenge expires after 60 seconds |
| Card number validation | Luhn algorithm enforced on the frontend |
| Certificate validity | 1-year expiry; expiry and revocation checked on every sensitive operation |

**Known limitations (by design):**
- Payment processing is always simulated as successful, because The focus of the payment module is cryptographic security, not banking integration.
- Password hashing uses SHA-256 without salt; a production system should use bcrypt or Argon2.
- The challenge store is in-memory and does not survive server restarts.

---

## Getting Started

### Prerequisites

```bash
pip install fastapi uvicorn httpx cryptography redis pillow pyjwt python-dotenv
```

Redis must be running locally on port 6379.

### Environment Variables

Copy `.env.example` to `.env` and fill in your secret key:

```bash
cp .env.example .env
```

`.env.example`:
```
SECRET_KEY=replace_with_a_strong_random_string
```

### Running

When redis is running, start all three servers in separate terminals:

```bash
# Terminal 1 - CA server (must start first)
python CA_server.py

# Terminal 2 - Payment gateway
python gateway_server.py

# Terminal 3 - Main server
python main.py
```

Then open `http://localhost:8100` in your browser.

> The CA server must be started first. The payment gateway registers its certificate with the CA on startup.

---

## License

MIT License

Copyright (c) 2026 Hanbo Fan

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
