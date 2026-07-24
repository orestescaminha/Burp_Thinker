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

# simple in-memory background task store
_tasks = {}


def run_background(task_id, func, *args, **kwargs):
    def wrapper():
        try:
            _tasks[task_id]["status"] = "running"
            # The result from the conversation manager is already a clean dict
            _tasks[task_id]["result"] = func(*args, **kwargs)
            _tasks[task_id]["status"] = "done"
        except Exception as e:
            _tasks[task_id]["status"] = "error"
            _tasks[task_id]["result"] = {"error": str(e)}
    t = threading.Thread(target=wrapper, daemon=True)
    t.start()


def auth_check(authorization: Optional[str]):
    token = os.getenv("BURP_THINKER_TOKEN", "local-secret")
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = authorization.split()
    
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. Expected 'Bearer <token>'")

    if parts[1] != token:
        raise HTTPException(status_code=403, detail="Invalid token")


@router.post("/analyze/request")
async def analyze_request(payload: dict, request: Request, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    raw = payload.get("request", "")
    check_size_limits(raw, max_kb=64)
    key = sha256_text(raw + "analyze_request")
    
    # Use a dictionary for the cache key to be safe
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
async def analyze_response(payload: dict, request: Request, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    raw = payload.get("response", "")
    check_size_limits(raw, max_kb=512)
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
async def payloads_sqli(payload: dict, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    param = payload.get("parameter") or "id"
    dbms = payload.get("dbms") or "mysql"
    key = sha256_text(param + dbms + "sqli")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "payloads": cached}

    res = conv.generate_sqli(param, dbms)
    # normalize
    if isinstance(res, dict) and "payloads" in res:
        payloads = res["payloads"]
    elif isinstance(res, list):
        payloads = res
    else:
        payloads = [str(res)]

    cache.set(key, payloads)
    return {"payloads": payloads}


@router.post("/payloads/xss")
async def payloads_xss(payload: dict, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    context = payload.get("context", "generic") # e.g., "html_tag_attribute", "javascript_string"
    key = sha256_text(context + "xss")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "payloads": cached}

    res = conv.generate_xss(context)
    
    # Normalize response to always be a list of strings
    if isinstance(res, dict) and "payloads" in res:
        payloads = res["payloads"]
    elif isinstance(res, list):
        payloads = res
    else:
        payloads = [str(res)]

    cache.set(key, payloads)
    return {"payloads": payloads}


@router.post("/explain/stack_trace")
async def explain_stack_trace(payload: dict, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    stack_trace = payload.get("stack_trace", "")
    if not stack_trace:
        raise HTTPException(status_code=400, detail="stack_trace field is required")

    key = sha256_text(stack_trace + "explain_stack_trace")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "result": cached}

    result = conv.explain_stack_trace(stack_trace)
    cache.set(key, result)
    return result


@router.post("/suggest/fuzzing_strategy")
async def suggest_fuzzing_strategy(payload: dict, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    context = payload.get("context", "")
    if not context:
        raise HTTPException(status_code=400, detail="context field is required")

    key = sha256_text(context + "fuzzing_strategy")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "result": cached}

    result = conv.suggest_fuzzing_strategy(context)
    cache.set(key, result)
    return result


@router.post("/summarize/crawl")
async def summarize_crawl(payload: dict, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    crawl_data = payload.get("crawl_data", "")
    if not crawl_data:
        raise HTTPException(status_code=400, detail="crawl_data field is required")

    key = sha256_text(crawl_data + "summarize_crawl")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "result": cached}

    result = conv.summarize_crawl(crawl_data)
    cache.set(key, result)
    return result


@router.post("/generate/turbo_intruder_script")
async def generate_turbo_intruder_script(payload: dict, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    base_request = payload.get("base_request", "")
    if not base_request:
        raise HTTPException(status_code=400, detail="base_request field is required")

    key = sha256_text(base_request + "generate_turbo_intruder_script")
    cached = cache.get(key)
    if cached:
        return {"cached": True, "result": cached}

    result = conv.generate_turbo_intruder_script(base_request)
    cache.set(key, result)
    return result


@router.post("/jwt")
async def analyze_jwt(payload: dict, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
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
async def get_task(task_id: str, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    t = _tasks.get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="task not found")
    return {"task_id": task_id, "status": t["status"], "result": t["result"]}


# Streaming endpoints (SSE) - optional, requires provider support
from fastapi.responses import StreamingResponse


@router.get("/stream/analyze/request")
async def stream_analyze_request(request: Request, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    # Expect raw request in query param or headers for streaming proxies (limited use-case)
    return HTTPException(status_code=501, detail="Streaming not supported in this deployment")


@router.get("/stream/analyze/response")
async def stream_analyze_response(request: Request, authorization: str = Header(..., description="Bearer token for authorization, e.g., 'Bearer local-secret'")):
    auth_check(authorization)
    return HTTPException(status_code=501, detail="Streaming not supported in this deployment")
