import os
import hashlib
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================
# CHAOTIC PREPROCESSING
# ==========================

def henon_map(data: bytes, a: float = 1.4, b: float = 0.3) -> bytes:
    x, y = 0.1, 0.1
    result = bytearray(len(data))
    for i in range(len(data)):
        x_new = 1 - a * x * x + y
        y_new = b * x
        x, y = x_new, y_new
        chaos_byte = int(abs(x) * 256) % 256
        result[i] = data[i] ^ chaos_byte
    return bytes(result)


def logistic_map(data: bytes, r: float = 3.99) -> bytes:
    x = 0.5
    result = bytearray(len(data))
    for i in range(len(data)):
        x = r * x * (1 - x)
        chaos_byte = int(x * 256) % 256
        result[i] = data[i] ^ chaos_byte
    return bytes(result)


def chaotic_preprocess(data: bytes) -> bytes:
    data = henon_map(data)
    data = logistic_map(data)
    return data


# ==========================
# AES-256-GCM ENCRYPTION
# ==========================

def generate_shard_key(master_key: str, shard_id: str, file_id: str) -> bytes:
    combined = f"{master_key}:{shard_id}:{file_id}"
    return hashlib.sha256(combined.encode()).digest()


def encrypt_shard(data: bytes, key: bytes) -> tuple:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)
    return nonce, encrypted


def decrypt_shard(nonce: bytes, encrypted: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted, None)


# ==========================
# VARIABLE SIZE SHARDING
# ==========================

def create_variable_shards(data: bytes, num_shards: int) -> list:
    total = len(data)
    boundaries = sorted(
        [0] + [int(abs(np.random.normal(total / num_shards, total / (num_shards * 4)))) 
               for _ in range(num_shards - 1)] + [total]
    )
    shards = []
    pos = 0
    for i in range(num_shards):
        size = max(1, boundaries[i + 1] - boundaries[i]) if i < len(boundaries) - 1 else total - pos
        shards.append(data[pos:pos + size])
        pos += size
        if pos >= total:
            break
    return shards


# ==========================
# DECOY SHARD GENERATION
# ==========================

def generate_decoy_shard(size: int = None) -> bytes:
    if size is None:
        size = int(abs(np.random.normal(1024, 256)))
    return os.urandom(max(64, size))