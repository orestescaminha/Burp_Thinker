import os

# These JSON structures are derived from the Pydantic models in schemas.py
# and are used to guide the LLM.

REQUEST_ANALYSIS_JSON_STRUCTURE = """
{
  "summary": "string",
  "interesting_parameters": ["string"],
  "possible_vulnerabilities": ["string"],
  "attack_surface": "string",
  "headers_of_interest": { "string": "string" }
}
"""

RESPONSE_ANALYSIS_JSON_STRUCTURE = """
{
  "status_code": "integer",
  "interesting_headers": { "string": "string" },
  "cookies": ["string"],
  "framework_detected": "string",
  "potential_info_disclosure": ["string"],
  "security_headers": { "string": "string" },
  "vulnerability_indicators": ["string"]
}
"""

CSP_ANALYSIS_JSON_STRUCTURE = """
{
  "summary": "string",
  "directives": { "directive-name": "directive-value-and-explanation" },
  "weaknesses": ["string"],
  "recommendations": ["string"]
}
"""

def build_request_analysis_prompt(raw_http: str) -> str:
    """Build a detailed, locale-aware prompt for request analysis."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()
    
    if locale.startswith("en"):
        instruction = "Analyze the following HTTP request from a pentesting perspective. Respond ONLY with a valid JSON object matching the structure below. Do not include markdown formatting or any extra text."
    else: # default: Portuguese
        instruction = "Analise a seguinte requisição HTTP da perspectiva de um pentest. Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua formatação markdown ou qualquer texto extra."

    return f"""{instruction}

JSON Structure:
{REQUEST_ANALYSIS_JSON_STRUCTURE}

HTTP Request:
```http
{raw_http}
```
"""

def build_response_analysis_prompt(raw_http: str) -> str:
    """Build a detailed, locale-aware prompt for response analysis."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = "Analyze the following HTTP response from a pentesting perspective. Respond ONLY with a valid JSON object matching the structure below. Do not include markdown formatting or any extra text."
    else: # default: Portuguese
        instruction = "Analise a seguinte resposta HTTP da perspectiva de um pentest. Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua formatação markdown ou qualquer texto extra."

    return f"""{instruction}

JSON Structure:
{RESPONSE_ANALYSIS_JSON_STRUCTURE}

HTTP Response:
```http
{raw_http}
```
"""

def build_xss_payload_prompt(context: str) -> str:
    """Build a prompt for generating XSS payloads based on a given context."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = f"For security testing purposes, generate a list of diverse XSS test vectors for the following context: '{context}'. The examples should demonstrate various encoding and obfuscation techniques. Respond ONLY with a valid JSON array of strings. Do not include markdown or any extra text."
    else: # default: Portuguese
        instruction = f"Para fins de teste de segurança, gere uma lista de vetores de teste XSS diversificados para o seguinte contexto: '{context}'. Os exemplos devem demonstrar várias técnicas de codificação e ofuscação. Responda APENAS com um array JSON válido de strings. Não inclua markdown ou qualquer texto extra."

    return f"""{instruction}

Example Response:
[
    "<script>alert(1)</script>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<img src=x onerror=alert(1)>"
]
"""

def build_csp_explanation_prompt(csp_header: str) -> str:
    """Build a prompt for explaining a Content Security Policy (CSP) header."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = "Analyze the following Content Security Policy (CSP) header. Explain each directive, identify security weaknesses, and provide recommendations for improvement. Respond ONLY with a valid JSON object matching the structure below. Do not include markdown or any extra text."
    else: # default: Portuguese
        instruction = "Analise o seguinte cabeçalho de Content Security Policy (CSP). Explique cada diretiva, identifique pontos fracos de segurança e forneça recomendações de melhoria. Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua formatação markdown ou qualquer texto extra."

    return f"""{instruction}

JSON Structure:
{CSP_ANALYSIS_JSON_STRUCTURE}

CSP Header:
`{csp_header}`
"""

STACK_TRACE_ANALYSIS_JSON_STRUCTURE = """
{
  "error_summary": "string",
  "likely_root_cause": "string",
  "potential_vulnerabilities": ["string"],
  "mitigation_recommendations": ["string"],
  "code_context": "string (optional)"
}
"""

def build_stack_trace_explanation_prompt(stack_trace: str) -> str:
    """Build a prompt for explaining a stack trace."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = "Analyze the following stack trace. Provide a summary of the error, its likely root cause, any potential security vulnerabilities it might expose, and recommendations for mitigation. Respond ONLY with a valid JSON object matching the structure below. Do not include markdown or any extra text."
    else: # default: Portuguese
        instruction = "Analise o seguinte stack trace. Forneça um resumo do erro, sua provável causa raiz, quaisquer vulnerabilidades de segurança potenciais que ele possa expor e recomendações para mitigação. Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua formatação markdown ou qualquer texto extra."

    return f"""{instruction}

JSON Structure:
{STACK_TRACE_ANALYSIS_JSON_STRUCTURE}

Stack Trace:
```
{stack_trace}
```
"""

FUZZING_STRATEGY_JSON_STRUCTURE = """
{
  "summary": "string",
  "fuzzing_targets": ["string"],
  "data_types_to_fuzz": ["string"],
  "recommended_tools": ["string"],
  "potential_vulnerabilities_to_find": ["string"],
  "notes": "string (optional)"
}
"""

def build_fuzzing_strategy_prompt(context: str) -> str:
    """Build a prompt for suggesting a fuzzing strategy based on an HTTP request/response context."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = "Analyze the following HTTP request or response context and suggest a comprehensive fuzzing strategy. Identify specific targets, data types, recommended tools, and potential vulnerabilities to uncover. Respond ONLY with a valid JSON object matching the structure below. Do not include markdown or any extra text."
    else: # default: Portuguese
        instruction = "Analise o seguinte contexto de requisição ou resposta HTTP e sugira uma estratégia de fuzzing abrangente. Identifique alvos específicos, tipos de dados, ferramentas recomendadas e vulnerabilidades potenciais a serem descobertas. Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua formatação markdown ou qualquer texto extra."

    return f"""{instruction}

JSON Structure:
{FUZZING_STRATEGY_JSON_STRUCTURE}

HTTP Context:
```http
{context}
```
"""

CRAWL_SUMMARY_JSON_STRUCTURE = """
{
  "summary": "string",
  "interesting_urls": ["string"],
  "detected_technologies": ["string"],
  "potential_vulnerabilities": ["string"],
  "areas_for_further_investigation": ["string"]
}
"""

def build_crawl_summary_prompt(crawl_data: str) -> str:
    """Build a prompt for summarizing crawl data."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = "Analyze the following crawl data (list of URLs, sitemap, etc.) and provide a concise summary of the application/website. Identify interesting URLs, detected technologies, potential vulnerabilities, and areas for further investigation. Respond ONLY with a valid JSON object matching the structure below. Do not include markdown or any extra text."
    else: # default: Portuguese
        instruction = "Analise os seguintes dados de crawl (lista de URLs, sitemap, etc.) e forneça um resumo conciso da aplicação/site. Identifique URLs interessantes, tecnologias detectadas, vulnerabilidades potenciais e áreas para investigação adicional. Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua formatação markdown ou qualquer texto extra."

    return f"""{instruction}

JSON Structure:
{CRAWL_SUMMARY_JSON_STRUCTURE}

Crawl Data:
```
{crawl_data}
```
"""

SECURITY_ASSESSMENT_JSON_STRUCTURE = """
{
  "findings": [
    {
      "title": "string",
      "severity": "string (High, Medium, Low, Informational)",
      "evidence": "string (brief quote from request/response)",
      "description": "string",
      "confidence": "string (Confirmed, Potential)",
      "next_steps": "string (actionable steps to confirm)"
    }
  ]
}
"""

def build_security_assessment_prompt(raw_request: str, raw_response: str) -> str:
    """Build a prompt for a full security assessment of an HTTP request/response pair."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = """
As a senior web application vulnerability analyst, analyze the provided HTTP request and response pair to produce a precise and evidence-based security assessment.

**CRITICAL RULES:**
- Be objective and factual. Base every statement on observable evidence from the provided data.
- DO NOT repeat the full request/response; cite only the minimal snippets necessary as evidence.
- If a vulnerability is only suspected, explicitly classify its `confidence` as "Potential" and clearly state the `next_steps` to confirm it.
- If no relevant risk is found, return an empty `findings` list.

Respond ONLY with a valid JSON object matching the structure below. Do not include markdown or any extra text.
"""
    else: # default: Portuguese
        instruction = """
Como um analista sênior de vulnerabilidades em aplicações web, analise o par de requisição e resposta HTTP fornecido para produzir uma avaliação de segurança precisa e fundamentada em evidências.

**REGRAS CRÍTICAS:**
- Seja objetivo e factual. Baseie cada afirmação em evidências observáveis nos dados fornecidos.
- NÃO repita a requisição/resposta na íntegra; cite apenas os trechos mínimos necessários como evidência.
- Caso a vulnerabilidade seja apenas uma suspeita, classifique sua `confidence` explicitamente como "Potencial" e indique claramente os `next_steps` para confirmá-la.
- Se não houver risco relevante, retorne uma lista `findings` vazia.

Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua markdown ou qualquer texto extra.
"""

    return f"""{instruction}

JSON Structure:
{SECURITY_ASSESSMENT_JSON_STRUCTURE}

=== REQUEST ===
```http
{raw_request}
```

=== RESPONSE ===
```http
{raw_response}
```
"""


TURBO_INTRUDER_SCRIPT_JSON_STRUCTURE = """
{
  "script_code": "string (Python code for Turbo Intruder)",
  "explanation": "string (explanation of the script's purpose and usage)",
  "suggested_payloads": ["string"]
}
"""

def build_turbo_intruder_script_prompt(base_request: str) -> str:
    """Build a prompt for generating a Turbo Intruder script based on a base HTTP request."""
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()

    if locale.startswith("en"):
        instruction = "Generate a Python script for Burp Suite's Turbo Intruder based on the following HTTP request. The script should be designed for a common security testing scenario (e.g., brute-forcing, parameter discovery, timing attacks). Provide the script code, an explanation of its purpose and how to use it, and suggested payloads. Respond ONLY with a valid JSON object matching the structure below. Do not include markdown or any extra text."
    else: # default: Portuguese
        instruction = "Gere um script Python para o Turbo Intruder do Burp Suite com base na seguinte requisição HTTP. O script deve ser projetado para um cenário comum de teste de segurança (por exemplo, força bruta, descoberta de parâmetros, ataques de temporização). Forneça o código do script, uma explicação de seu propósito e como usá-lo, e payloads sugeridos. Responda APENAS com um objeto JSON válido que corresponda à estrutura abaixo. Não inclua formatação markdown ou qualquer texto extra."

    return f"""{instruction}

JSON Structure:
{TURBO_INTRUDER_SCRIPT_JSON_STRUCTURE}

Base HTTP Request:
```http
{base_request}
```
"""