import hmac, hashlib, base64, json, time

UPLOAD_SECRET = "super_secret_key"

def generate_upload_token(file_id, shard_id, node_id):

    payload = {
        "file_id": file_id,
        "shard_id": shard_id,
        "node_id": node_id,
        "exp": int(time.time()) + 300
    }

    data = json.dumps(payload).encode()

    signature = hmac.new(
        UPLOAD_SECRET.encode(),
        data,
        hashlib.sha256
    ).digest()

    token = base64.urlsafe_b64encode(data + b"." + signature).decode()

    return token


def verify_upload_token(token):

    decoded = base64.urlsafe_b64decode(token.encode())
    data, signature = decoded.rsplit(b".", 1)

    expected = hmac.new(
        UPLOAD_SECRET.encode(),
        data,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(signature, expected):
        return None

    payload = json.loads(data)

    if payload["exp"] < time.time():
        return None

    return payload