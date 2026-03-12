from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError

from app.database.db import (
    uploads_collection,
    nodes_collection,
    shards_collection,
    keys_collection,
    join_codes_collection
)

import random
import hmac
import hashlib
import base64
import uuid
import time
import string
import asyncio

app = FastAPI()

UPLOAD_SECRET = "super_secret_key"
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


class NodeRequest(BaseModel):
    node_name: str
    ip_address: str
    storage_capacity: int


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

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):

    token = credentials.credentials

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ==========================
# SIGNED SHARD TOKEN
# ==========================

def generate_upload_token(file_id, shard_id, node_id, expiry):

    payload = f"{file_id}:{shard_id}:{node_id}:{expiry}"

    signature = hmac.new(
        UPLOAD_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).digest()

    token = base64.urlsafe_b64encode(signature).decode()

    return token


# ==========================
# BACKGROUND WORKER
# ==========================

async def recovery_worker():

    while True:

        print("Running background recovery check...")

        current_time = time.time()

        nodes = list(nodes_collection.find())

        for node in nodes:

            last_seen = node.get("last_seen")

            if last_seen and current_time - last_seen > 30:

                nodes_collection.update_one(
                    {"node_id": node["node_id"]},
                    {"$set": {"status": "OFFLINE"}}
                )

        shards = list(shards_collection.find())
        active_nodes = list(nodes_collection.find({"status": "ACTIVE"}))

        for shard in shards:

            if "primary_node" not in shard or "replica_node" not in shard:
                continue

            primary_node = shard["primary_node"]
            replica_node = shard["replica_node"]

            primary_status = nodes_collection.find_one({"node_id": primary_node})

            if primary_status and primary_status["status"] == "OFFLINE":

                new_primary = replica_node

                candidates = [
                    n for n in active_nodes
                    if n["node_id"] != new_primary
                ]

                if candidates:

                    new_replica = random.choice(candidates)

                    shards_collection.update_one(
                        {"_id": shard["_id"]},
                        {"$set": {
                            "primary_node": new_primary,
                            "replica_node": new_replica["node_id"]
                        }}
                    )

        await asyncio.sleep(10)


@app.on_event("startup")
async def start_background_tasks():
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

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# ==========================
# NODE MANAGEMENT
# ==========================

@app.post("/generate-join-code")
def generate_join_code():

    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    join_codes_collection.insert_one({
        "code": code,
        "used": False
    })

    return {"join_code": code}


@app.post("/join-cluster")
def join_cluster(request: JoinClusterRequest):

    code_entry = join_codes_collection.find_one({
        "code": request.join_code,
        "used": False
    })

    if not code_entry:
        return {"error": "Invalid or used join code"}

    node_id = str(uuid.uuid4())

    nodes_collection.insert_one({
        "node_id": node_id,
        "node_name": request.node_name,
        "ip_address": request.ip_address,
        "storage_capacity": request.storage_capacity,
        "status": "ACTIVE"
    })

    join_codes_collection.update_one(
        {"code": request.join_code},
        {"$set": {"used": True}}
    )

    return {"message": "Node joined cluster", "node_id": node_id}


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

    upload_data = {
        "file_id": file_id,
        "external_file_id": request.external_file_id,
        "theatre_id": request.theatre_id,
        "total_shards": request.total_shards,
        "status": "UPLOADING"
    }

    uploads_collection.insert_one(upload_data)

    return {"message": "Upload session created", "file_id": file_id}


@app.post("/upload-key")
def upload_key(request: UploadKeyRequest):

    key_id = str(uuid.uuid4())

    keys_collection.insert_one({
        "key_id": key_id,
        "encrypted_key": request.encryption_key
    })

    uploads_collection.update_one(
        {"external_file_id": request.file_id},
        {"$set": {"key_id": key_id}}
    )

    return {"message": "Key stored", "key_id": key_id}


@app.post("/upload-manifest")
def upload_manifest(manifest: UploadManifestRequest, user=Depends(verify_token)):

    upload = uploads_collection.find_one(
        {"external_file_id": manifest.file_id}
    )

    if not upload:
        return {"error": "File not found"}

    if upload["total_shards"] != manifest.total_shards:
        return {"error": "Shard count mismatch"}

    uploads_collection.update_one(
        {"external_file_id": manifest.file_id},
        {"$set": {
            "hash_algorithm": manifest.hash_algorithm,
            "status": "MANIFEST_RECEIVED"
        }}
    )

    return {"message": "Manifest validated", "file_id": manifest.file_id}


@app.post("/complete-upload")
def complete_upload(request: CompleteUploadRequest, user=Depends(verify_token)):

    uploads_collection.update_one(
        {"external_file_id": request.file_id},
        {"$set": {"status": "ACTIVE"}}
    )

    return {"message": "Upload completed", "file_id": request.file_id}


# ==========================
# SHARD ALLOCATION
# ==========================

@app.post("/request-shard-upload")
def request_shard_upload(shard: ShardRequest, user=Depends(verify_token)):

    nodes = list(nodes_collection.find({"status": "ACTIVE"}))

    if len(nodes) < 2:
        return {"error": "At least two nodes required"}

    existing = shards_collection.find_one({
        "file_id": shard.file_id,
        "shard_id": shard.shard_id
    })

    if existing:
        return {"error": "Shard already allocated"}

    primary = random.choice(nodes)

    replica = random.choice([
        n for n in nodes if n["node_id"] != primary["node_id"]
    ])

    expiry = int(time.time()) + 300

    primary_token = generate_upload_token(
        shard.file_id,
        shard.shard_id,
        primary["node_id"],
        expiry
    )

    replica_token = generate_upload_token(
        shard.file_id,
        shard.shard_id,
        replica["node_id"],
        expiry
    )

    # SAVE SHARD METADATA
    shards_collection.insert_one({
        "file_id": shard.file_id,
        "shard_id": shard.shard_id,
        "primary_node": primary["node_id"],
        "replica_node": replica["node_id"]
    })

    primary_url = f"http://{primary['ip_address']}:9000/upload?token={primary_token}"
    replica_url = f"http://{replica['ip_address']}:9000/upload?token={replica_token}"

    return {
        "primary_upload_url": primary_url,
        "replica_upload_url": replica_url,
        "expires_in": 300
    }


# ==========================
# FILE METADATA
# ==========================

@app.get("/file/{file_id}")
def get_file_shards(file_id: str):

    shards = list(shards_collection.find({"file_id": file_id}, {"_id": 0}))

    if not shards:
        return {"message": "No shards found"}

    return {"file_id": file_id, "shards": shards}