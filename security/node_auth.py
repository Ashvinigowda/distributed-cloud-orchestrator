import jwt
import time

JWT_SECRET = "node_secret"
ALGO = "HS256"

def generate_node_token(node_id):

    payload = {
        "node_id": node_id,
        "exp": int(time.time()) + 86400
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=ALGO)


def verify_node_token(token):

    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
    except:
        return None