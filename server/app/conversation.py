from .providers import ProviderFactory
from .prompt_builder import build_request_analysis_prompt, build_response_analysis_prompt, build_xss_payload_prompt, build_csp_explanation_prompt, build_stack_trace_explanation_prompt, build_fuzzing_strategy_prompt, build_crawl_summary_prompt, build_turbo_intruder_script_prompt, build_security_assessment_prompt
from .schemas import RequestAnalysis, ResponseAnalysis, FallbackAnalysis, CSPAnalysis, StackTraceAnalysis, FuzzingStrategy, CrawlSummary, TurboIntruderScript, SecurityAssessment
from .utils import safe_parse_jwt
import os
import logging
from typing import Any, Dict, Union
import json
from pydantic import ValidationError

logger = logging.getLogger(__name__)

class ConversationManager:
    def __init__(self, providers: ProviderFactory, cache):
        self.providers = providers
        self.cache = cache
        self.provider_name = os.getenv("BURP_THINKER_PROVIDER", "gemini")

    def _get_and_validate_analysis(self, prompt: str, model: Union[RequestAnalysis, ResponseAnalysis, SecurityAssessment, FuzzingStrategy, CrawlSummary, TurboIntruderScript, StackTraceAnalysis, CSPAnalysis]) -> Dict[str, Any]:
        """Generic function to get analysis from a provider and validate against a Pydantic model."""
        provider = self.providers.get(self.provider_name)
        response = provider.complete(prompt)
        raw_text = response.get("result", "")

        # First, clean the raw text to remove markdown fences and extra whitespace.
        cleaned_text = raw_text.strip()
        if cleaned_text.startswith("```json"):
            cleaned_text = cleaned_text[7:].strip()
        elif cleaned_text.startswith("```"):
            cleaned_text = cleaned_text[3:].strip()
        
        if cleaned_text.endswith("```"):
            cleaned_text = cleaned_text[:-3].strip()

        try:
            # First, try to parse the string into a Python dictionary
            parsed_json = json.loads(cleaned_text)
            
            # Then, validate the dictionary against the Pydantic model
            validated_data = model.model_validate(parsed_json)
            return validated_data.model_dump()
            
        except (ValidationError, json.JSONDecodeError) as e:
            logger.error(f"Failed to parse or validate LLM response for schema {model.__name__}. Error: {e}. Raw text: {raw_text}")
            # If any parsing or validation fails, return the raw text within the fallback schema.
            return FallbackAnalysis(analysis_text=f"Error processing AI response: {e}\n\nRaw Response:\n{raw_text}").model_dump()

    def analyze_request(self, raw_http: str) -> Dict[str, Any]:
        """Builds a prompt, gets the analysis, and validates it against the RequestAnalysis schema."""
        prompt = build_request_analysis_prompt(raw_http)
        return self._get_and_validate_analysis(prompt, RequestAnalysis)

    def analyze_response(self, raw_http: str) -> Dict[str, Any]:
        """Builds a prompt, gets the analysis, and validates it against the ResponseAnalysis schema."""
        prompt = build_response_analysis_prompt(raw_http)
        return self._get_and_validate_analysis(prompt, ResponseAnalysis)

    def explain_csp(self, csp_header: str) -> Dict[str, Any]:
        """Builds a prompt, gets the analysis for a CSP header, and validates it."""
        prompt = build_csp_explanation_prompt(csp_header)
        return self._get_and_validate_analysis(prompt, CSPAnalysis)

    def explain_stack_trace(self, stack_trace: str) -> Dict[str, Any]:
        """Builds a prompt, gets the analysis for a stack trace, and validates it."""
        prompt = build_stack_trace_explanation_prompt(stack_trace)
        return self._get_and_validate_analysis(prompt, StackTraceAnalysis)

    def suggest_fuzzing_strategy(self, context: str) -> Dict[str, Any]:
        """Builds a prompt, gets a fuzzing strategy, and validates it."""
        prompt = build_fuzzing_strategy_prompt(context)
        return self._get_and_validate_analysis(prompt, FuzzingStrategy)

    def summarize_crawl(self, crawl_data: str) -> Dict[str, Any]:
        """Builds a prompt, gets a crawl summary, and validates it."""
        prompt = build_crawl_summary_prompt(crawl_data)
        return self._get_and_validate_analysis(prompt, CrawlSummary)

    def analyze_http_pair(self, raw_request: str, raw_response: str) -> Dict[str, Any]:
        """Builds a prompt for a full security assessment of a req/res pair and validates it."""
        prompt = build_security_assessment_prompt(raw_request, raw_response)
        return self._get_and_validate_analysis(prompt, SecurityAssessment)

    def generate_turbo_intruder_script(self, base_request: str) -> Dict[str, Any]:
        """Builds a prompt, gets a Turbo Intruder script, and validates it."""
        prompt = build_turbo_intruder_script_prompt(base_request)
        return self._get_and_validate_analysis(prompt, TurboIntruderScript)

    def generate_xss(self, context: str) -> Dict[str, Any]:
        """Builds a prompt and gets XSS payloads from the provider."""
        prompt = build_xss_payload_prompt(context)
        response = self.providers.get(self.provider_name).complete(prompt)
        raw_text = response.get("result", "")
        
        try:
            # Payloads are expected to be a simple JSON array of strings
            payloads = json.loads(raw_text)
            if isinstance(payloads, list):
                return payloads
        except (json.JSONDecodeError, TypeError):
            # If parsing fails, log the problematic response and return a fallback list
            logger.error(f"Failed to parse XSS payloads from LLM. Raw response was: {raw_text}")
        
        return ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

    def generate_sqli(self, parameter, dbms):
        provider = self.providers.get(self.provider_name)
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
            result_text = resp.get("result")
            
            # Attempt to parse JSON array from provider result
            parsed = json.loads(result_text)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass # Fallback to base list if parsing fails
        return base

    def analyze_jwt(self, token):
        # This can remain simple as it doesn't rely on complex LLM responses
        return safe_parse_jwt(token)
