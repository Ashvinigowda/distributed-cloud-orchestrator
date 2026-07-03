import logging
import json
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from security.middleware import node_auth_middleware

from app.database.db import (
    uploads_collection,
    nodes_collection,
    shards_collection,
    keys_collection,
    join_codes_collection
)

from security.token import generate_upload_token
from security.vault import encrypt_key
from security.node_auth import generate_node_token

import random
import uuid
import time
import string
import asyncio

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI()
app.add_middleware(BaseHTTPMiddleware, dispatch=node_auth_middleware)

JWT_SECRET = "orchestrator_secret_key"
JWT_ALGORITHM = "HS256"

security = HTTPBearer()

# ==========================
# MODELS
# ==========================

class UploadRequest(BaseModel):
    external_file_id: str
    theatre_id: str
    total_shards: int
    playback_start: float
    playback_end: float

class ShardRequest(BaseModel):
    file_id: str
    shard_id: str

class HeartbeatRequest(BaseModel):
    node_id: str

class JoinClusterRequest(BaseModel):
    join_code: str
    node_name: str
    ip_address: str
    storage_capacity: int

class UploadManifestRequest(BaseModel):
    file_id: str
    total_shards: int
    hash_algorithm: str
    shards: list

class CompleteUploadRequest(BaseModel):
    file_id: str

class UploadKeyRequest(BaseModel):
    file_id: str
    encryption_key: str


# ==========================
# JWT AUTH
# ==========================

def create_access_token(client_id: str):
    payload = {
        "client_id": client_id,
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ==========================
# BACKGROUND WORKER
# ==========================

async def recovery_worker():
    while True:
        current_time = time.time()
        nodes = list(nodes_collection.find())

        for node in nodes:
            last_seen = node.get("last_seen")
            if last_seen and current_time - last_seen > 30:
                nodes_collection.update_one(
                    {"node_id": node["node_id"]},
                    {"$set": {"status": "OFFLINE"}}
                )
                logger.warning(f"Node {node['node_id']} marked OFFLINE")

        shards = list(shards_collection.find())
        active_nodes = list(nodes_collection.find({"status": "ACTIVE"}))

        for shard in shards:
            primary_node = shard.get("primary_node")
            replica_node = shard.get("replica_node")
            primary_status = nodes_collection.find_one({"node_id": primary_node})

            if primary_status and primary_status["status"] == "OFFLINE":
                new_primary = replica_node
                candidates = [n for n in active_nodes if n["node_id"] != new_primary]

                if candidates:
                    new_replica = random.choice(candidates)
                    shards_collection.update_one(
                        {"_id": shard["_id"]},
                        {"$set": {
                            "primary_node": new_primary,
                            "replica_node": new_replica["node_id"]
                        }}
                    )
                    logger.info(f"Shard {shard['shard_id']} recovered — new primary: {new_primary}")

        await asyncio.sleep(10)


@app.on_event("startup")
async def start_background_tasks():
    logger.info("Shard Orchestrator started")
    asyncio.create_task(recovery_worker())


# ==========================
# ROOT
# ==========================

@app.get("/")
def home():
    return {"message": "Shard Orchestrator Running"}


# ==========================
# AUTH
# ==========================

@app.post("/auth/login")
def login():
    token = create_access_token("trusted_client")
    logger.info("Client login successful")
    return {"access_token": token, "token_type": "bearer"}


# ==========================
# NODE MANAGEMENT
# ==========================

@app.post("/generate-join-code")
def generate_join_code():
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    join_codes_collection.insert_one({"code": code, "used": False})
    logger.info(f"Join code generated: {code}")
    return {"join_code": code}


@app.post("/join-cluster")
def join_cluster(request: JoinClusterRequest):
    code_entry = join_codes_collection.find_one({"code": request.join_code, "used": False})

    if not code_entry:
        raise HTTPException(status_code=400, detail="Invalid or used join code")

    node_id = str(uuid.uuid4())

    nodes_collection.insert_one({
        "node_id": node_id,
        "node_name": request.node_name,
        "ip_address": request.ip_address,
        "storage_capacity": request.storage_capacity,
        "status": "ACTIVE"
    })

    join_codes_collection.update_one({"code": request.join_code}, {"$set": {"used": True}})
    node_token = generate_node_token(node_id)
    logger.info(f"Node joined: {node_id} ({request.node_name})")

    return {
        "message": "Node joined cluster",
        "node_id": node_id,
        "node_token": node_token
    }


@app.post("/heartbeat")
def heartbeat(heartbeat: HeartbeatRequest):
    nodes_collection.update_one(
        {"node_id": heartbeat.node_id},
        {"$set": {"last_seen": time.time(), "status": "ACTIVE"}}
    )
    return {"message": "Heartbeat received"}


# ==========================
# UPLOAD LIFECYCLE
# ==========================

@app.post("/init-upload")
def init_upload(request: UploadRequest, user=Depends(verify_token)):
    file_id = str(uuid.uuid4())
    uploads_collection.insert_one({
        "file_id": file_id,
        "external_file_id": request.external_file_id,
        "theatre_id": request.theatre_id,
        "total_shards": request.total_shards,
        "playback_start": request.playback_start,
        "playback_end": request.playback_end,
        "status": "UPLOADING"
    })
    logger.info(f"Upload initiated: {file_id}")
    return {"file_id": file_id}


@app.post("/upload-key")
def upload_key(request: UploadKeyRequest):
    key_id = str(uuid.uuid4())
    encrypted = encrypt_key(request.encryption_key)
    keys_collection.insert_one({"key_id": key_id, "encrypted_key": encrypted})
    uploads_collection.update_one(
        {"external_file_id": request.file_id},
        {"$set": {"key_id": key_id}}
    )
    logger.info(f"Encryption key stored: {key_id}")
    return {"key_id": key_id}


@app.post("/upload-manifest")
def upload_manifest(manifest: UploadManifestRequest, user=Depends(verify_token)):
    upload = uploads_collection.find_one({"external_file_id": manifest.file_id})

    if not upload:
        raise HTTPException(status_code=404, detail="File not found")

    if upload["total_shards"] != manifest.total_shards:
        raise HTTPException(status_code=400, detail="Shard count mismatch")

    if len(manifest.shards) != manifest.total_shards:
        raise HTTPException(status_code=400, detail="Shard list length does not match total_shards")

    uploads_collection.update_one(
        {"external_file_id": manifest.file_id},
        {"$set": {
            "hash_algorithm": manifest.hash_algorithm,
            "shards": manifest.shards,
            "status": "MANIFEST_RECEIVED"
        }}
    )

    manifest_data = {
        "file_id": manifest.file_id,
        "total_shards": manifest.total_shards,
        "hash_algorithm": manifest.hash_algorithm,
        "shards": manifest.shards,
        "generated_at": time.time()
    }

    manifest_path = f"manifests/{manifest.file_id}.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest_data, f, indent=2)

    logger.info(f"Manifest validated and saved: {manifest_path}")
    return {"message": "Manifest validated", "manifest_path": manifest_path}


@app.post("/complete-upload")
def complete_upload(request: CompleteUploadRequest, user=Depends(verify_token)):
    upload = uploads_collection.find_one({"external_file_id": request.file_id})

    if not upload:
        raise HTTPException(status_code=404, detail="File not found")

    uploaded_count = shards_collection.count_documents({"file_id": upload["file_id"]})

    if uploaded_count < upload["total_shards"]:
        raise HTTPException(
            status_code=400,
            detail=f"Only {uploaded_count} of {upload['total_shards']} shards uploaded"
        )

    uploads_collection.update_one(
        {"external_file_id": request.file_id},
        {"$set": {"status": "ACTIVE"}}
    )
    logger.info(f"Upload completed: {request.file_id}")
    return {"message": "Upload completed"}


# ==========================
# SHARD ALLOCATION
# ==========================

@app.post("/request-shard-upload")
def request_shard_upload(shard: ShardRequest, user=Depends(verify_token)):
    nodes = list(nodes_collection.find({"status": "ACTIVE"}))

    if len(nodes) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 nodes")

    existing = shards_collection.find_one({
        "file_id": shard.file_id,
        "shard_id": shard.shard_id
    })
    if existing:
        raise HTTPException(status_code=400, detail="Shard already allocated")

    primary = random.choice(nodes)
    replica = random.choice([n for n in nodes if n["node_id"] != primary["node_id"]])

    primary_token = generate_upload_token(shard.file_id, shard.shard_id, primary["node_id"])
    replica_token = generate_upload_token(shard.file_id, shard.shard_id, replica["node_id"])

    shards_collection.insert_one({
        "file_id": shard.file_id,
        "shard_id": shard.shard_id,
        "primary_node": primary["node_id"],
        "replica_node": replica["node_id"]
    })

    logger.info(f"Shard {shard.shard_id} allocated — primary: {primary['node_id']}, replica: {replica['node_id']}")

    return {
        "primary_upload_url": f"http://{primary['ip_address']}:9000/upload?token={primary_token}",
        "replica_upload_url": f"http://{replica['ip_address']}:9000/upload?token={replica_token}",
        "expires_in": 300
    }


# ==========================
# FILE RETRIEVAL
# ==========================

@app.get("/file/{file_id}")
def get_file_shards(file_id: str):
    upload = uploads_collection.find_one({"file_id": file_id})

    if not upload:
        raise HTTPException(status_code=404, detail="File not found")

    current_time = time.time()

    if current_time < upload["playback_start"]:
        raise HTTPException(status_code=403, detail="Playback window not started yet")

    if current_time > upload["playback_end"]:
        raise HTTPException(status_code=403, detail="Playback window has expired")

    shards = list(shards_collection.find({"file_id": file_id}, {"_id": 0}))

    if not shards:
        return {"message": "No shards found"}

    logger.info(f"File retrieved: {file_id}")
    return {"file_id": file_id, "shards": shards}