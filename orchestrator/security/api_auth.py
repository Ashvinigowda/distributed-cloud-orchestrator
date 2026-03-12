import hashlib
from config import API_SECRET

def verify_request(body, signature):

    computed = hashlib.sha256(
        (body + API_SECRET).encode()
    ).hexdigest()

    return computed == signature