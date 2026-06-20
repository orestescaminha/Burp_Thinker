from .providers import ProviderFactory
from .prompt_builder import build_request_analysis_prompt, build_response_analysis_prompt
from .utils import safe_parse_jwt
import os

class ConversationManager:
    def __init__(self, providers: ProviderFactory, cache):
        self.providers = providers
        self.cache = cache
        self.provider_name = os.getenv("BURP_THINKER_PROVIDER", "openai")

    def analyze_request(self, raw):
        prompt = build_request_analysis_prompt(raw)
        provider = self.providers.get(self.provider_name)
        resp = provider.complete(prompt)
        return {"summary": resp.get("result")}

    def analyze_response(self, raw):
        prompt = build_response_analysis_prompt(raw)
        provider = self.providers.get(self.provider_name)
        resp = provider.complete(prompt)
        return {"analysis": resp.get("result")}

    def generate_sqli(self, parameter, dbms):
        base = [
            f"'{parameter}' OR '1'='1'--",
            '" OR 1=1--',
            "1; DROP TABLE users; --",
            "' OR sleep(5)--"
        ]
        provider = self.providers.get(self.provider_name)
        prompt = f"Generate SQLi payloads for parameter {parameter} targeting {dbms}. Return a JSON array only."
        resp = provider.complete(prompt)
        return base

    def analyze_jwt(self, token):
        return safe_parse_jwt(token)
