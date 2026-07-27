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

def optimize_http_payload(raw: str, max_body_kb: int = 10) -> str:
    """
    Parses a raw HTTP message and truncates the body if it exceeds max_body_kb.
    Keeps the headers completely intact.
    """
    try:
        parsed = parse_raw_http(raw)
        body = parsed["body"]
        body_bytes = body.encode("utf-8")
        
        if len(body_bytes) > max_body_kb * 1024:
            truncated_body = body_bytes[:max_body_kb * 1024].decode("utf-8", "replace")
            note = f"\r\n\r\n[... BODY TRUNCATED BY BURP THINKER FOR OPTIMIZATION. ORIGINAL SIZE: {len(body_bytes)} BYTES ...]\r\n"
            
            # Reconstruct the HTTP message with truncated body
            headers_str = "\r\n".join([f"{k}: {v}" for k, v in parsed["headers"].items()])
            reconstructed = f"{parsed['start_line']}\r\n{headers_str}\r\n\r\n{truncated_body}{note}"
            return reconstructed
    except Exception:
        pass # Fallback to original if parsing fails
    return raw

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
