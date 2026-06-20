from .providers import ProviderFactory
from .prompt_builder import build_request_analysis_prompt, build_response_analysis_prompt
from .utils import safe_parse_jwt
import os
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

class ConversationManager:
    def __init__(self, providers: ProviderFactory, cache):
        self.providers = providers
        self.cache = cache
        self.provider_name = os.getenv("BURP_THINKER_PROVIDER", "openai")

    def analyze_request(self, raw) -> Dict[str, Any]:
        """Return structured analysis for an HTTP request.
        If the configured provider exposes a structured analyze_request method (e.g. Gemini), use it.
        Otherwise build a prompt and call the generic complete() method and return a best-effort structure.
        """
        provider = self.providers.get(self.provider_name)

        # Prefer provider-specific structured API when available
        if hasattr(provider, "analyze_request_structured"):
            try:
                return provider.analyze_request_structured(raw)
            except Exception as e:
                logger.exception("Provider structured analyze_request failed, falling back: %s", e)

        # Fallback: generic prompt
        prompt = build_request_analysis_prompt(raw)
        resp = provider.complete(prompt)
        return {"summary": resp.get("result")}

    def analyze_response(self, raw) -> Dict[str, Any]:
        provider = self.providers.get(self.provider_name)
        if hasattr(provider, "analyze_response_structured"):
            try:
                return provider.analyze_response_structured(raw)
            except Exception as e:
                logger.exception("Provider structured analyze_response failed, falling back: %s", e)
        prompt = build_response_analysis_prompt(raw)
        resp = provider.complete(prompt)
        return {"analysis": resp.get("result")}

    def generate_sqli(self, parameter, dbms):
        provider = self.providers.get(self.provider_name)
        # Prefer structured generator
        if hasattr(provider, "generate_sqli_payloads"):
            try:
                res = provider.generate_sqli_payloads(parameter, dbms)
                # normalize to a simple list of payloads if possible
                if isinstance(res, dict) and "payloads" in res:
                    return res["payloads"]
                return res
            except Exception as e:
                logger.exception("Provider generate_sqli_payloads failed, falling back: %s", e)

        # Fallback small built-in payload list + provider augmentation
        base = [
            f"'{parameter}' OR '1'='1'--",
            '" OR 1=1--',
            "1; DROP TABLE users; --",
            "' OR sleep(5)--"
        ]
        try:
            prompt = f"Generate SQLi payloads for parameter {parameter} targeting {dbms}. Return a JSON array only."
            resp = provider.complete(prompt)
            # attempt to parse JSON array from provider result
            result_text = resp.get("result")
            # quick JSON extract
            import json
            try:
                parsed = json.loads(result_text)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
        except Exception:
            pass
        return base

    def analyze_jwt(self, token):
        provider = self.providers.get(self.provider_name)
        if hasattr(provider, "analyze_jwt_structured"):
            try:
                return provider.analyze_jwt_structured(token)
            except Exception as e:
                logger.exception("Provider analyze_jwt_structured failed, falling back: %s", e)
        return safe_parse_jwt(token)
