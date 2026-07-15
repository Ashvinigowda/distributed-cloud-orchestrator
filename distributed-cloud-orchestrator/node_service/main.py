import logging
import uuid
import hashlib
import os
import httpx
import asyncio
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.token import verify_upload_token
from node_service.encryption import (
    chaotic_preprocess,
    generate_shard_key,
    encrypt_shard,
    generate_decoy_shard
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI()

NODE_ID = os.getenv("NODE_ID", "node-001")
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://127.0.0.1:8000")
MASTER_KEY = os.getenv("MASTER_KEY", "default_master_key")
SHARD_STORAGE_PATH = "node_service/shards"

os.makedirs(SHARD_STORAGE_PATH, exist_ok=True)


# ==========================
# MODELS
# ==========================

class ReplicateRequest(BaseModel):
    shard_id: str
    file_id: str
    shard_data: str


# ==========================
# HEARTBEAT BACKGROUND TASK
# ==========================

async def send_heartbeat():
    while True:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{ORCHESTRATOR_URL}/heartbeat",
                    json={"node_id": NODE_ID}
                )
                logger.info(f"Heartbeat sent for node: {NODE_ID}")
        except Exception as e:
            logger.warning(f"Heartbeat failed: {e}")
        await asyncio.sleep(10)


@app.on_event("startup")
async def startup():
    logger.info(f"Node service started — Node ID: {NODE_ID}")
    asyncio.create_task(send_heartbeat())


# ==========================
# ROOT
# ==========================

@app.get("/")
def home():
    return {"message": f"Node {NODE_ID} running"}


# ==========================
# HEALTH CHECK
# ==========================

@app.get("/health")
def health():
    shard_count = len(os.listdir(SHARD_STORAGE_PATH))
    return {
        "node_id": NODE_ID,
        "status": "ACTIVE",
        "shards_stored": shard_count
    }


# ==========================
# SHARD UPLOAD
# ==========================

@app.put("/upload")
async def upload_shard(token: str, file: UploadFile = File(...)):

    payload = verify_upload_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if payload["node_id"] != NODE_ID:
        raise HTTPException(status_code=403, detail="Token not valid for this node")

    shard_data = await file.read()

    # Step 1 — Chaotic preprocessing
    preprocessed = chaotic_preprocess(shard_data)
    logger.info(f"Chaotic preprocessing done for shard: {payload['shard_id']}")

    # Step 2 — Generate per-shard key
    shard_key = generate_shard_key(MASTER_KEY, payload["shard_id"], payload["file_id"])

    # Step 3 — AES-256-GCM encryption
    nonce, encrypted = encrypt_shard(preprocessed, shard_key)
    logger.info(f"Shard encrypted: {payload['shard_id']}")

    # Step 4 — Compute hash of encrypted data
    computed_hash = hashlib.sha256(encrypted).hexdigest()

    # Step 5 — Store nonce + encrypted shard together
    shard_path = f"{SHARD_STORAGE_PATH}/{payload['shard_id']}.bin"
    with open(shard_path, "wb") as f:
        f.write(nonce + encrypted)

    # Step 6 — Generate and store a decoy shard
    decoy_path = f"{SHARD_STORAGE_PATH}/decoy_{payload['shard_id']}.bin"
    with open(decoy_path, "wb") as f:
        f.write(generate_decoy_shard(len(shard_data)))
    logger.info(f"Decoy shard created for: {payload['shard_id']}")

    # Step 7 — Notify orchestrator
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ORCHESTRATOR_URL}/confirm-shard",
                json={
                    "file_id": payload["file_id"],
                    "shard_id": payload["shard_id"],
                    "node_id": NODE_ID,
                    "sha256": computed_hash
                }
            )
            logger.info(f"Shard confirmed with orchestrator: {payload['shard_id']}")
    except Exception as e:
        logger.warning(f"Could not confirm shard with orchestrator: {e}")

    return {
        "message": "Shard uploaded, encrypted and stored",
        "shard_id": payload["shard_id"],
        "sha256": computed_hash
    }


# ==========================
# SHARD REPLICATION
# ==========================

@app.post("/replicate")
def replicate_shard(request: ReplicateRequest):

    shard_data = bytes.fromhex(request.shard_data)
    computed_hash = hashlib.sha256(shard_data).hexdigest()

    shard_path = f"{SHARD_STORAGE_PATH}/{request.shard_id}.bin"
    with open(shard_path, "wb") as f:
        f.write(shard_data)

    logger.info(f"Shard replicated: {request.shard_id} | SHA256: {computed_hash}")

    return {
        "message": "Shard replicated successfully",
        "shard_id": request.shard_id,
        "sha256": computed_hash
    }

# ==========================
# SPLIT AND UPLOAD FULL FILE
# ==========================

@app.post("/split-and-upload")
async def split_and_upload(file_id: str, num_shards: int, file: UploadFile = File(...)):

    file_data = await file.read()
    logger.info(f"Received file for splitting: {file_id} — size: {len(file_data)} bytes")

    # Step 1 — Split into variable size shards
    from node_service.encryption import create_variable_shards
    shards = create_variable_shards(file_data, num_shards)
    logger.info(f"Split into {len(shards)} variable-size shards")

    results = []

    for i, shard_data in enumerate(shards):
        shard_id = str(uuid.uuid4())

        # Step 2 — Chaotic preprocessing
        preprocessed = chaotic_preprocess(shard_data)

        # Step 3 — Generate per-shard key
        shard_key = generate_shard_key(MASTER_KEY, shard_id, file_id)

        # Step 4 — AES-256-GCM encryption
        nonce, encrypted = encrypt_shard(preprocessed, shard_key)

        # Step 5 — Compute hash
        computed_hash = hashlib.sha256(encrypted).hexdigest()

        # Step 6 — Store shard
        shard_path = f"{SHARD_STORAGE_PATH}/{shard_id}.bin"
        with open(shard_path, "wb") as f:
            f.write(nonce + encrypted)

        # Step 7 — Generate decoy
        decoy_path = f"{SHARD_STORAGE_PATH}/decoy_{shard_id}.bin"
        with open(decoy_path, "wb") as f:
            f.write(generate_decoy_shard(len(shard_data)))

        # Step 8 — Notify orchestrator
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{ORCHESTRATOR_URL}/confirm-shard",
                    json={
                        "file_id": file_id,
                        "shard_id": shard_id,
                        "node_id": NODE_ID,
                        "sha256": computed_hash
                    }
                )
        except Exception as e:
            logger.warning(f"Could not confirm shard {shard_id}: {e}")

        results.append({
            "shard_id": shard_id,
            "size": len(shard_data),
            "sha256": computed_hash
        })

        logger.info(f"Shard {i+1}/{len(shards)} processed: {shard_id}")

    return {
        "message": "File split and uploaded successfully",
        "file_id": file_id,
        "total_shards": len(results),
        "shards": results
    }