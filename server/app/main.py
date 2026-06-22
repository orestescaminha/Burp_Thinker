from fastapi import FastAPI
from .routes import router
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, Response

app = FastAPI(title="Burp Thinker API", version="0.1.0")
app.include_router(router)

# Mount a minimal static frontend for quick UI and docs link
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.isdir(static_dir):
    try:
        os.makedirs(static_dir, exist_ok=True)
    except Exception:
        pass

app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    """Redirect root to static index (simple frontend)"""
    return RedirectResponse(url="/static/")


@app.get("/favicon.ico")
async def favicon():
    """Return a tiny SVG as favicon to avoid 404 in browsers"""
    svg = '<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">\n  <rect width="16" height="16" rx="3" fill="#4F46E5"/>\n  <text x="8" y="11" font-size="9" text-anchor="middle" fill="white" font-family="Arial, Helvetica, sans-serif">BT</text>\n</svg>'
    return Response(content=svg, media_type="image/svg+xml")

# Security: only bind to 127.0.0.1 at runtime (uvicorn --host 127.0.0.1)
# Env: API token in BURP_THINKER_TOKEN
if "BURP_THINKER_TOKEN" not in os.environ:
    # not fatal here, but recommend .env or env var set
    pass
