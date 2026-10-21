"""
ThreatLens - Enterprise Email Threat Investigation Platform
FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router as api_router
from backend.api.graphops_routes import router as graphops_router
from backend.graphops.client import close_graphops_client
from backend.core.config import STATIC_DIR


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Application startup
    yield
    # Application shutdown: safely close graph database connection pool
    close_graphops_client()


app = FastAPI(
    title="ThreatLens API",
    description="Enterprise Email Threat Investigation, Forensics, Threat Intelligence & Campaign Correlation Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# Enable CORS for local testing and dev workflows
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router (existing routes)
app.include_router(api_router, prefix="/api/v1")

# Include GraphOps router (additive security graph routes)
app.include_router(graphops_router, prefix="/api/v1/graphops", tags=["GraphOps"])

# Mount Static Frontend
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")

@app.get("/")
def root():
    return {
        "message": "Welcome to ThreatLens API",
        "docs_url": "/docs",
        "frontend_url": "/static/index.html"
    }
