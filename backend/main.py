"""
ThreatLens - Enterprise Email Threat Investigation Platform
FastAPI Application Entry Point
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router as api_router
from backend.core.config import STATIC_DIR

app = FastAPI(
    title="ThreatLens API",
    description="Enterprise Email Threat Investigation, Forensics, Threat Intelligence & Campaign Correlation Platform",
    version="2.0.0"
)

# Enable CORS for local testing and dev workflows
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")

# Mount Static Frontend
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")

@app.get("/")
def root():
    return {
        "message": "Welcome to ThreatLens API",
        "docs_url": "/docs",
        "frontend_url": "/static/index.html"
    }
