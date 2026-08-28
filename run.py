"""
ThreatLens - Server Launcher
Enterprise Email Threat Investigation Platform
"""

import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("  ThreatLens v2.0 — AI-Powered Email Forensics Platform")
    print("  Web UI:   http://127.0.0.1:8000/static/index.html")
    print("  API Docs: http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
