"""
MailTrace AI - Server Launcher
Feature 1: AI Threat Detection
"""

import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("Starting MailTrace AI - Feature 1 (AI Threat Detection)")
    print("Access Web UI at: http://127.0.0.1:8000")
    print("API Documentation: http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
