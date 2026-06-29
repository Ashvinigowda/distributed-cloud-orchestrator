import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

_raw_key = os.getenv("MASTER_KEY")

if not _raw_key:
    raise RuntimeError("MASTER_KEY not found in .env")

cipher = Fernet(_raw_key.encode())

def encrypt_key(key: str) -> str:
    return cipher.encrypt(key.encode()).decode()

def decrypt_key(enc_key: str) -> str:
    return cipher.decrypt(enc_key.encode()).decode()