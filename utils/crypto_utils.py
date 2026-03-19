# crypto_utils.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Generate RSA-2048 key pair, return private key object + priv_pem + pub_pem
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, priv_pem, pub_pem

# PKCS1v15 and SHA-256, return hex
def sign_data(private_key, data: str) -> str:
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

# Verify a PKCS1v15 SHA256 signature given a PEM public key
def verify_signature_with_pem(public_key_pem: str, data: str, signature_hex: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        assert isinstance(public_key, RSAPublicKey)
        public_key.verify(
            bytes.fromhex(signature_hex),
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
