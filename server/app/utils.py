import hashlib, json
import jwt

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def check_size_limits(s: str, max_kb: int = 128):
    b = s.encode("utf-8")
    if len(b) > max_kb * 1024:
        raise ValueError(f"payload too large ({len(b)} bytes)")

def parse_raw_http(raw: str):
    parts = raw.split("\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = header_block.split("\r\n")
    start = lines[0] if lines else ""
    headers = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            headers[k.strip()] = v.strip()
    return {"start_line": start, "headers": headers, "body": body}

def safe_parse_jwt(token: str):
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        issues = []
        alg = header.get("alg")
        if alg in ("none", None):
            issues.append("alg none or missing")
        if "exp" not in payload:
            issues.append("no exp claim")
        return {"algorithm": alg, "claims": payload, "issues": issues, "suggestions": ["Try to validate signature", "Check exp/nbf/aud/clm"]}
    except Exception as e:
        return {"error": str(e)}
