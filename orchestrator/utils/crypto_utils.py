import hashlib

def sha256(data):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()