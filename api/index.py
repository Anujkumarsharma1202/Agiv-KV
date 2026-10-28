"""
Vercel Serverless Entrypoint for Aegis-KV Gateway.
Exposes the FastAPI application to Vercel Python runtime.
"""
import sys
from pathlib import Path

# Ensure workspace root is in sys.path so 'gateway' package is discoverable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from gateway.main import app

# Expose app and handler for Vercel serverless ASGI detection
handler = app
