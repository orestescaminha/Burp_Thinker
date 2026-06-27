# server/app/gemini_integration.py
"""
Gemini Integration Module
Handles Google Generative AI (Gemini) API calls with robust error handling,
parsing, and response normalization. Tries to use google.genai (new package)
and falls back to google.generativeai (deprecated package) when needed.
"""
import os
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Prefer the new package if available, else fallback to the older deprecated package.
GENAI_AVAILABLE = False
GENAI_VARIANT = None
genai = None
try:
    # new package (recommended): google-genai, import path: google.genai
    import google.genai as genai  # type: ignore
    GENAI_AVAILABLE = True
    GENAI_VARIANT = "genai"
    logger.debug("Using google.genai (new) for Gemini integration")
except Exception:
    try:
        # older/deprecated package: google-generativeai
        import google.generativeai as genai  # type: ignore
        GENAI_AVAILABLE = True
        GENAI_VARIANT = "generativeai"
        logger.debug("Using google.generativeai (deprecated) for Gemini integration")
    except Exception:
        GENAI_AVAILABLE = False
        genai = None
        GENAI_VARIANT = None
        logger.warning("No Google Gemini SDK available; Gemini provider will return stubs.")

class GeminiClient:
    """Wrapper around Google Generative AI client with proper configuration and error handling."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-pro")
        self.client = None
        # We don't eagerly instantiate a client for all SDK variants; handle at call time.
        self.variant = GENAI_VARIANT
        self.lib = genai

    def is_available(self) -> bool:
        """Check if Gemini is properly configured and available."""
        return self.lib is not None and bool(self.api_key)

    def generate(
        self,
        prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.7,
        top_p: float = 0.95,
        top_k: int = 40
    ) -> Dict[str, Any]:
        """
        Generate content using Gemini API.
        Returns:
            Dict with keys: 'result' (text), 'status' (success/error/stub), 'metadata' (model/usage info)
        """
        if not self.is_available():
            return {
                "result": f"[Gemini stub: prompt length {len(prompt)}]",
                "status": "stub",
                "metadata": {"reason": "Gemini not available"}
            }

        try:
            # Attempt several common API patterns depending on the installed SDK variant.
            # New google.genai usage may differ; we try known shapes and fall back gracefully.

            # If using the older google.generativeai package
            if self.variant == "generativeai":
                try:
                    # configure if supported
                    if hasattr(self.lib, "configure"):
                        self.lib.configure(api_key=self.api_key)
                    # Try chat completions style (common in some versions)
                    if hasattr(self.lib, "chat") and hasattr(self.lib.chat, "completions"):
                        resp = self.lib.chat.completions.create(
                            model=self.model_name,
                            messages=[{"role": "user", "content": prompt}],
                            max_output_tokens=max_tokens
                        )
                    else:
                        # fallback to a generic generate_content or generate call if available
                        if hasattr(self.lib, "GenerativeModel"):
                            model = self.lib.GenerativeModel(self.model_name)
                            resp = model.generate_content(prompt, generation_config=getattr(self.lib, "types", None))
                        elif hasattr(self.lib, "generate"):
                            resp = self.lib.generate(prompt)
                        else:
                            raise RuntimeError("Unsupported google.generativeai SDK shape")
                    result_text = self._parse_response(resp)
                    return {
                        "result": result_text,
                        "status": "success",
                        "metadata": {
                            "model": self.model_name,
                            "prompt_tokens": len(prompt.split()),
                            "completion_tokens": len(result_text.split()) if result_text else 0
                        }
                    }
                except Exception as e:
                    logger.exception("Error using google.generativeai path")
                    raise

            # If using the newer google.genai package (best-effort compatibility)
            elif self.variant == "genai":
                try:
                    # The new google.genai library has different APIs across versions.
                    # Try common patterns:
                    # 1) genai.chat.completions.create(...)
                    if hasattr(self.lib, "chat") and hasattr(self.lib.chat, "completions"):
                        resp = self.lib.chat.completions.create(
                            model=self.model_name,
                            messages=[{"role": "user", "content": prompt}],
                            max_output_tokens=max_tokens
                        )
                        result_text = self._parse_response(resp)
                    # 2) genai.generate_text(...) or genai.generate(...)
                    elif hasattr(self.lib, "generate_text"):
                        resp = self.lib.generate_text(model=self.model_name, text=prompt, max_output_tokens=max_tokens)
                        result_text = self._parse_response(resp)
                    elif hasattr(self.lib, "generate"):
                        resp = self.lib.generate(model=self.model_name, prompt=prompt, max_output_tokens=max_tokens)
                        result_text = self._parse_response(resp)
                    # 3) object-oriented client: genai.GenerativeModel(...)
                    elif hasattr(self.lib, "GenerativeModel"):
                        client = self.lib.GenerativeModel(self.model_name)
                        # try generate_content or generate_text
                        if hasattr(client, "generate_content"):
                            resp = client.generate_content(prompt)
                            result_text = self._parse_response(resp)
                        elif hasattr(client, "generate_text"):
                            resp = client.generate_text(prompt)
                            result_text = self._parse_response(resp)
                        else:
                            raise RuntimeError("Unsupported google.genai GenerativeModel API")
                    else:
                        # Last resort: attempt a generic call
                        resp = self.lib.generate(prompt) if hasattr(self.lib, "generate") else str(self.lib)
                        result_text = self._parse_response(resp)
                    return {
                        "result": result_text,
                        "status": "success",
                        "metadata": {
                            "model": self.model_name,
                            "prompt_tokens": len(prompt.split()),
                            "completion_tokens": len(result_text.split()) if result_text else 0
                        }
                    }
                except Exception as e:
                    logger.exception("Error using google.genai path")
                    raise

            else:
                raise RuntimeError("No supported Gemini SDK variant found")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Gemini generation error: {error_msg}")
            return {
                "result": f"[Gemini error: {error_msg}]",
                "status": "error",
                "metadata": {"error": error_msg}
            }

    @staticmethod
    def _parse_response(response: Any) -> str:
        """
        Parse Gemini API response and extract text content.
        Handles various response formats from different SDK versions.
        """
        try:
            # If response has 'text' attribute
            if response is None:
                return ""
            if isinstance(response, str):
                return response
            if hasattr(response, "text"):
                return response.text

            # Some SDKs return a mapping/dict
            if isinstance(response, dict):
                # common keys: 'candidates', 'choices', 'output', 'content'
                if "candidates" in response and response["candidates"]:
                    candidate = response["candidates"][0]
                    if isinstance(candidate, dict):
                        # candidate['content'] might be dict with parts or text
                        content = candidate.get("content")
                        if isinstance(content, dict):
                            parts = content.get("parts") or []
                            if parts:
                                return parts[0].get("text", str(parts[0]))
                            return str(content)
                        return str(content)
                    return str(candidate)
                if "choices" in response and response["choices"]:
                    ch = response["choices"][0]
                    # try known shapes
                    if isinstance(ch, dict):
                        if "message" in ch:
                            msg = ch["message"]
                            if isinstance(msg, dict):
                                return msg.get("content", "")
                            return str(msg)
                        return ch.get("text", str(ch))
                # generic fallback to 'output' or 'content' keys
                for k in ("output", "content", "result"):
                    if k in response:
                        return str(response[k])
                # fallback to stringified dict
                return json.dumps(response)

            # Try attributes like candidates/choices with nested structures
            if hasattr(response, "candidates") and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, "content"):
                    content = candidate.content
                    if hasattr(content, "parts") and content.parts:
                        part = content.parts[0]
                        if hasattr(part, "text"):
                            return part.text
                        return str(part)
                    return str(content)
            if hasattr(response, "candidates") and len(response.candidates) > 0:
                return str(response.candidates[0])
            if hasattr(response, "choices") and len(response.choices) > 0:
                ch = response.choices[0]
                if hasattr(ch, "message"):
                    msg = ch.message
                    if isinstance(msg, dict):
                        return msg.get("content", "")
                    return getattr(msg, "content", str(msg))
                return getattr(ch, "text", str(ch))

            # Fallback to string representation
            return str(response)

        except Exception as e:
            logger.warning(f"Failed to parse Gemini response: {e}")
            return f"[Response parsing error: {e}]"


class GeminiPromptBuilder:
    """Specialized prompt building for Gemini with optimization for pentest analysis."""

    @staticmethod
    def request_analysis_prompt(raw_http: str) -> str:
        """Build optimized prompt for HTTP request analysis."""
        return f"""Analise esta requisição HTTP para pentest. Responda em JSON com os seguintes campos:

{{
  "summary": "resumo breve da requisição",
  "interesting_parameters": ["param1", "param2"],
  "possible_vulnerabilities": ["vuln1", "vuln2"],
  "methods": ["GET", "POST"],
  "headers_of_interest": {{"header1": "valor1"}},
  "attack_surface": "descrição da superfície de ataque"
}}

Requisição HTTP:
{raw_http}

Responda APENAS com JSON válido, sem markdown ou comentários."""

    @staticmethod
    def response_analysis_prompt(raw_http: str) -> str:
        """Build optimized prompt for HTTP response analysis."""
        return f"""Analise esta resposta HTTP para pentest. Responda em JSON com os seguintes campos:

{{
  "status_code": 200,
  "reflected_parameters": ["param1"],
  "interesting_headers": {{"header": "value"}},
  "cookies": ["cookie1=value1"],
  "framework_detected": "Framework/Version",
  "potential_info_disclosure": ["info1"],
  "security_headers": {{"header": "present/missing"}},
  "vulnerabilities_indicators": ["xss", "sqli"]
}}

Resposta HTTP:
{raw_http}

Responda APENAS com JSON válido, sem markdown ou comentários."""

    @staticmethod
    def jwt_analysis_prompt(token: str) -> str:
        """Build optimized prompt for JWT analysis."""
        return f"""Analise este JWT token de segurança. Responda em JSON com:

{{
  "algorithm": "alg",
  "claims_summary": {{"key": "value"}},
  "security_issues": ["issue1"],
  "recommendations": ["recom1"],
  "risk_level": "high/medium/low"
}}

JWT Token:
{token}

Responda APENAS com JSON válido, sem markdown ou comentários."""

    @staticmethod
    def sqli_payload_prompt(parameter: str, dbms: str) -> str:
        """Build optimized prompt for SQLi payload generation."""
        return f"""Gere payloads SQLi para o parâmetro '{parameter}' em um banco de dados {dbms}. 
Responda com um JSON array APENAS:

[
  "payload1",
  "payload2",
  "payload3"
]

Sem explicações, apenas os payloads entre aspas duplas."""


class GeminiResponseParser:
    """Parse and validate Gemini responses, extracting structured data."""

    @staticmethod
    def try_extract_json(text: str) -> Optional[Dict[str, Any]]:
        """
        Attempt to extract valid JSON from Gemini response.
        Handles cases where JSON is wrapped in markdown code blocks.
        """
        if not text:
            return None

        # Remove markdown code blocks if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse JSON from response: {text[:100]}")
            return None

    @staticmethod
    def safe_parse_response(text: str, expected_keys: Optional[list] = None) -> Dict[str, Any]:
        """
        Safely parse Gemini response with fallback to raw text if JSON parsing fails.
        """
        parsed = GeminiResponseParser.try_extract_json(text)

        if parsed and isinstance(parsed, dict):
            # Validate expected keys if provided
            if expected_keys:
                missing = [k for k in expected_keys if k not in parsed]
                if missing:
                    logger.warning(f"Response missing expected keys: {missing}")
            return parsed

        # Fallback: return raw text wrapped in a dict
        return {
            "raw_response": text,
            "parsing_status": "fallback_to_text"
        }
