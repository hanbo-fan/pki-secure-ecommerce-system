# constants.py

class Role:
    CUSTOMER = "customer"
    MERCHANT = "merchant"
    GATEWAY  = "gateway"
    ALL      = ("customer", "merchant", "gateway")

class OrderStatus:
    PENDING_PAYMENT = "pending_payment"
    PAID            = "paid"

class CertStatus:
    ACTIVE  = "active"
    REVOKED = "revoked"