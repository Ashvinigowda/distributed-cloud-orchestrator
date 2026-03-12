import os
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
VAULT_MASTER_KEY = os.getenv("VAULT_MASTER_KEY").encode()
API_SECRET = os.getenv("API_SECRET")