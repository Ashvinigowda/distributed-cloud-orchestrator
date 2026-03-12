from fastapi import FastAPI
from routes.node_routes import router as node_router
from routes.key_routes import router as key_router

app = FastAPI()

app.include_router(node_router)
app.include_router(key_router)