"""
MailTrace AI - Main Application Server
Feature 1: AI Threat Detection
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.api.routes import router as api_router
from backend.core.config import APP_NAME, APP_VERSION, API_PREFIX

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="MailTrace AI - High-performance email threat investigation platform."
)

# Enable CORS for local dev and integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(api_router, prefix=API_PREFIX)

# Resolve path to frontend directory
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
frontend_dir = os.path.join(project_root, "frontend")

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_index():
        """Serves the primary MailTrace AI Feature 1 demonstration interface."""
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "MailTrace AI API is operational. Frontend index.html not found."}
