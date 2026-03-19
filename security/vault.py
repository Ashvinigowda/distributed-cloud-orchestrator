from cryptography.fernet import Fernet

MASTER_KEY = Fernet.generate_key()
cipher = Fernet(MASTER_KEY)

def encrypt_key(key: str):
    return cipher.encrypt(key.encode()).decode()

def decrypt_key(enc_key: str):
    return cipher.decrypt(enc_key.encode()).decode()