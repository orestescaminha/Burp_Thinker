from fastapi import APIRouter, Request, Header, HTTPException
from .cache import Cache
from .providers import ProviderFactory
from .utils import sha256_text, check_size_limits
from .conversation import ConversationManager
from typing import Optional
import os, uuid, threading

router = APIRouter()
cache = Cache("burp_thinker_cache.sqlite")
providers = ProviderFactory()
conv = ConversationManager(providers, cache)

_tasks = {}

def run_background(task_id, func, *args, **kwargs):
    def wrapper():
        try:
            _tasks[task_id]["status"] = "running"
            _tasks[task_id]["result"] = func(*args, **kwargs)
            _tasks[task_id]["status"] = "done"
        except Exception as e:
            _tasks[task_id]["status"] = "error"
            _tasks[task_id]["result"] = {"error": str(e)}
    t = threading.Thread(target=wrapper, daemon=True)
    t.start()

def auth_check(authorization: Optional[str]):
    token = os.getenv("BURP_THINKER_TOKEN", "local-secret")
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    if authorization.split()[1] != token:
        raise HTTPException(status_code=403, detail="Invalid token")

@router.post("/analyze/request")
async def analyze_request(payload: dict, request: Request, authorization: Optional[str] = Header(None)):
    auth_check(authorization)
    raw = payload.get("request", "")
    check_size_limits(raw, max_kb=64)
    key = sha256_text(raw + "analyze_request")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "result": cached}
    # support async mode
    if request.headers.get("X-Async") == "1":
        task_id = str(uuid.uuid4())
        _tasks[task_id] = {"status": "queued", "result": None}
        run_background(task_id, conv.analyze_request, raw)
        return {"task_id": task_id}, 202
    result = conv.analyze_request(raw)
    cache.set(key, result)
    return result

@router.post("/analyze/response")
async def analyze_response(payload: dict, request: Request, authorization: Optional[str] = Header(None)):
    auth_check(authorization)
    raw = payload.get("response", "")
    check_size_limits(raw, max_kb=128)
    key = sha256_text(raw + "analyze_response")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "result": cached}
    if request.headers.get("X-Async") == "1":
        task_id = str(uuid.uuid4())
        _tasks[task_id] = {"status": "queued", "result": None}
        run_background(task_id, conv.analyze_response, raw)
        return {"task_id": task_id}, 202
    result = conv.analyze_response(raw)
    cache.set(key, result)
    return result

@router.post("/payloads/sqli")
async def payloads_sqli(payload: dict, authorization: Optional[str] = Header(None)):
    auth_check(authorization)
    param = payload.get("parameter") or "id"
    dbms = payload.get("dbms") or "mysql"
    key = sha256_text(param + dbms + "sqli")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "payloads": cached}
    res = conv.generate_sqli(param, dbms)
    cache.set(key, res)
    return {"payloads": res}

@router.post("/jwt")
async def analyze_jwt(payload: dict, authorization: Optional[str] = Header(None)):
    auth_check(authorization)
    token = payload.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="token required")
    key = sha256_text(token + "jwt")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "result": cached}
    res = conv.analyze_jwt(token)
    cache.set(key, res)
    return res

@router.get("/tasks/{task_id}")
async def get_task(task_id: str, authorization: Optional[str] = Header(None)):
    auth_check(authorization)
    t = _tasks.get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="task not found")
    return {"task_id": task_id, "status": t["status"], "result": t["result"]}
