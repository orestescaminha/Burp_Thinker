import os

def build_request_analysis_prompt(raw_http: str):
    """Build a locale-aware prompt for request analysis.
    Locale controlled via BURP_THINKER_LOCALE environment variable (pt/en).
    """
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()
    if locale.startswith("en"):
        return f"Analyze this HTTP request for pentesting and return JSON with summary, interesting_parameters, possible_vulnerabilities. Request:\n\n{raw_http}"
    # default: Portuguese
    return f"Analise esta requisição HTTP para pentest e retorne JSON com summary, interesting_parameters, possible_vulnerabilities. Requisição:\n\n{raw_http}"


def build_response_analysis_prompt(raw_http: str):
    locale = os.getenv("BURP_THINKER_LOCALE", "pt").lower()
    if locale.startswith("en"):
        return f"Analyze this HTTP response for pentesting and return JSON with reflected_parameters, headers, cookies, framework_detection, potential_info_disclosure. Response:\n\n{raw_http}"
    return f"Analise esta resposta HTTP para pentest e retorne JSON com reflected_parameters, headers, cookies, framework_detection, potential_info_disclosure. Resposta:\n\n{raw_http}"
