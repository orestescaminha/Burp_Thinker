"""
Gemini Integration Module
Handles Google Generative AI (Gemini) API calls with robust error handling,
parsing, and response normalization.
"""

import os
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

try:
    import google.generativeai as genai
    from google.generativeai.types import GenerateContentResponse
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    logger.warning("google-generativeai SDK not installed. Gemini provider will return stubs.")

class GeminiClient:
    """Wrapper around Google Generative AI client with proper configuration and error handling."""
    
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-pro")
        self.client = None
        
        if GENAI_AVAILABLE and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel(self.model_name)
                logger.info(f"Gemini client initialized with model: {self.model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
                self.client = None
        else:
            if not GENAI_AVAILABLE:
                logger.debug("google-generativeai not available")
            if not self.api_key:
                logger.debug("GEMINI_API_KEY not set")
    
    def is_available(self) -> bool:
        """Check if Gemini is properly configured and available."""
        return self.client is not None and GENAI_AVAILABLE
    
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
            Dict with keys: 'result' (text), 'status' (success/error), 'metadata' (model/usage info)
        """
        if not self.is_available():
            return {
                "result": f"[Gemini stub: prompt length {len(prompt)}]",
                "status": "stub",
                "metadata": {"reason": "Gemini not available"}
            }
        
        try:
            # Prepare generation config
            generation_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                top_k=top_k
            )
            
            # Call Gemini API
            response = self.client.generate_content(
                prompt,
                generation_config=generation_config
            )
            
            # Parse and normalize response
            result = self._parse_response(response)
            
            return {
                "result": result,
                "status": "success",
                "metadata": {
                    "model": self.model_name,
                    "prompt_tokens": len(prompt.split()),  # rough estimate
                    "completion_tokens": len(result.split()) if result else 0
                }
            }
        
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
            # Try the standard response object format
            if hasattr(response, 'text'):
                return response.text
            
            # Try candidates format
            if hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content'):
                    content = candidate.content
                    if hasattr(content, 'parts') and content.parts:
                        part = content.parts[0]
                        if hasattr(part, 'text'):
                            return part.text
                        return str(part)
                    return str(content)
            
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
