from fastapi import APIRouter
from security.node_auth import generate_challenge, verify_signature
from security.token_service import generate_node_token

router = APIRouter()

challenge_store = {}

@router.post("/request-node-join")
def request_join(public_key: str):

    challenge = generate_challenge()

    challenge_store[public_key] = challenge

    return {"challenge": challenge}


@router.post("/verify-node")
def verify_node(public_key: str, signature: str):

    challenge = challenge_store[public_key]

    verify_signature(public_key, challenge, signature)

    node_token = generate_node_token("node123")

    return {"node_token": node_token}