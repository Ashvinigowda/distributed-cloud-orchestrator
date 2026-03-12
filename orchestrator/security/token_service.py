import jwt
import time
from config import JWT_SECRET

def generate_upload_token(node_id, shard_id, file_id):

    payload = {
        "node_id": node_id,
        "shard_id": shard_id,
        "file_id": file_id,
        "exp": int(time.time()) + 300
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return token


def verify_upload_token(token):

    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

    return payload


def generate_node_token(node_id):

    payload = {
        "node_id": node_id,
        "role": "node",
        "exp": int(time.time()) + 86400
    }

    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")