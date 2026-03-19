import os
import time
import uuid
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

challenge_store = {}

def create_challenge(public_key):

    challenge = os.urandom(32).hex()

    challenge_store[public_key] = {
        "challenge": challenge,
        "expires": time.time() + 300
    }

    return challenge


def verify_challenge(public_key_pem, signature):

    record = challenge_store.get(public_key_pem)

    if not record:
        return False

    if record["expires"] < time.time():
        return False

    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    public_key.verify(
        signature,
        record["challenge"].encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    del challenge_store[public_key_pem]

    return True