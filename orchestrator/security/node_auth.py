import base64
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# Generate random challenge
def generate_challenge():
    return secrets.token_hex(32)


# Verify signed challenge
def verify_signature(public_key_pem, challenge, signature):

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    public_key.verify(
        base64.b64decode(signature),
        challenge.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return True