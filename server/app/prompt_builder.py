def build_request_analysis_prompt(raw_http: str):
    return f"Analise esta requisição HTTP para pentest e retorne JSON com summary, interesting_parameters, possible_vulnerabilities. Requisição:\n\n{raw_http}"

def build_response_analysis_prompt(raw_http: str):
    return f"Analise esta resposta HTTP para pentest e retorne JSON com reflected_parameters, headers, cookies, framework_detection, potential_info_disclosure. Resposta:\n\n{raw_http}"
