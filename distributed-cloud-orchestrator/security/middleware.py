from fastapi import Request, HTTPException
from security.node_auth import verify_node_token

async def node_auth_middleware(request: Request, call_next):
    if request.url.path in ["/heartbeat", "/replicate"]:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            raise HTTPException(status_code=401, detail="Node token missing")
        payload = verify_node_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid node token")
    return await call_next(request)