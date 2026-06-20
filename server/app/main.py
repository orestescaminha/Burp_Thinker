from fastapi import FastAPI
from .routes import router
import os

app = FastAPI(title="Burp Thinker API", version="0.1.0")
app.include_router(router)

# Security: only bind to 127.0.0.1 at runtime (uvicorn --host 127.0.0.1)
# Env: API token in BURP_THINKER_TOKEN
if "BURP_THINKER_TOKEN" not in os.environ:
    # not fatal here, but recommend .env or env var set
    pass
