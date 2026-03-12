from fastapi import APIRouter
from security.vault_service import encrypt_key

router = APIRouter()

key_storage = {}

@router.post("/upload-key")
def upload_key(file_id: str, key: str):

    encrypted = encrypt_key(key)

    key_storage[file_id] = encrypted

    return {"status": "stored"}