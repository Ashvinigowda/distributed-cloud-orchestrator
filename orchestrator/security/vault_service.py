from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from config import VAULT_MASTER_KEY

def encrypt_key(key: str):

    cipher = AES.new(VAULT_MASTER_KEY, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(key.encode())

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def decrypt_key(data):

    cipher = AES.new(
        VAULT_MASTER_KEY,
        AES.MODE_EAX,
        nonce=base64.b64decode(data["nonce"])
    )

    key = cipher.decrypt_and_verify(
        base64.b64decode(data["ciphertext"]),
        base64.b64decode(data["tag"])
    )

    return key.decode()