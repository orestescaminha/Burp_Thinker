# /usr/lib/gemini-cli/Burp_Thinker/server/app/schemas.py
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class RequestAnalysis(BaseModel):
    """Defines the expected JSON structure for an HTTP request analysis."""
    summary: str = Field(..., description="Brief summary of the request's purpose and type.")
    interesting_parameters: List[str] = Field(default_factory=list, description="Parameters that could be interesting for security testing.")
    possible_vulnerabilities: List[str] = Field(default_factory=list, description="A list of potential vulnerability classes to investigate.")
    attack_surface: str = Field(default="", description="A description of the potential attack surface exposed by this endpoint.")
    headers_of_interest: Dict[str, str] = Field(default_factory=dict, description="Key-value pairs of HTTP headers that are noteworthy.")

class ResponseAnalysis(BaseModel):
    """Defines the expected JSON structure for an HTTP response analysis."""
    status_code: int = Field(..., description="The HTTP status code of the response.")
    interesting_headers: Dict[str, str] = Field(default_factory=dict, description="Key-value pairs of noteworthy HTTP headers (e.g., Server, X-Powered-By).")
    cookies: List[str] = Field(default_factory=list, description="A list of cookies set by the response.")
    framework_detected: str = Field(default="", description="The web framework or technology detected from the response.")
    potential_info_disclosure: List[str] = Field(default_factory=list, description="List of potential information disclosure findings.")
    security_headers: Dict[str, str] = Field(default_factory=dict, description="Analysis of security-related headers like CSP, HSTS, etc.")
    vulnerability_indicators: List[str] = Field(default_factory=list, description="Indicators of potential vulnerabilities (e.g., 'reflected XSS', 'error message').")

class FallbackAnalysis(BaseModel):
    """A fallback model for when the LLM response cannot be parsed into a specific schema."""
    analysis_text: str = Field(..., description="The raw text analysis from the AI.")

class CSPAnalysis(BaseModel):
    """Defines the expected JSON structure for a CSP analysis."""
    summary: str = Field(..., description="A high-level summary of the CSP's effectiveness.")
    directives: Dict[str, str] = Field(default_factory=dict, description="A breakdown of each directive and its meaning.")
    weaknesses: List[str] = Field(default_factory=list, description="A list of identified security weaknesses (e.g., 'unsafe-inline', broad sources).")
    recommendations: List[str] = Field(default_factory=list, description="Suggestions for improving the CSP.")

class StackTraceAnalysis(BaseModel):
    """Defines the expected JSON structure for a stack trace analysis."""
    error_summary: str = Field(..., description="A concise summary of the error identified in the stack trace.")
    likely_root_cause: str = Field(..., description="The probable root cause of the error.")
    potential_vulnerabilities: List[str] = Field(default_factory=list, description="Security vulnerabilities that might be indicated or caused by this error.")
    mitigation_recommendations: List[str] = Field(default_factory=list, description="Recommendations to fix the error and mitigate associated security risks.")
    code_context: Optional[str] = Field(None, description="Relevant code snippets or context extracted from the stack trace.")

class FuzzingStrategy(BaseModel):
    """Defines the expected JSON structure for a fuzzing strategy suggestion."""
    summary: str = Field(..., description="A high-level summary of the suggested fuzzing strategy.")
    fuzzing_targets: List[str] = Field(default_factory=list, description="Specific parameters, headers, or parts of the request/response to fuzz.")
    data_types_to_fuzz: List[str] = Field(default_factory=list, description="Types of data to use for fuzzing (e.g., integers, strings, special characters, SQLi payloads).")
    recommended_tools: List[str] = Field(default_factory=list, description="Tools that could be used for this fuzzing strategy (e.g., Burp Intruder, Ffuf).")
    potential_vulnerabilities_to_find: List[str] = Field(default_factory=list, description="Vulnerabilities that this strategy aims to uncover.")
    notes: Optional[str] = Field(None, description="Additional notes or considerations for the fuzzing process.")

class CrawlSummary(BaseModel):
    """Defines the expected JSON structure for a crawl summary."""
    summary: str = Field(..., description="A high-level summary of the crawled application/website.")
    interesting_urls: List[str] = Field(default_factory=list, description="URLs that appear particularly interesting for further security analysis.")
    detected_technologies: List[str] = Field(default_factory=list, description="Technologies or frameworks identified during the crawl.")
    potential_vulnerabilities: List[str] = Field(default_factory=list, description="Potential security vulnerabilities suggested by the crawl data.")
    areas_for_further_investigation: List[str] = Field(default_factory=list, description="Specific areas or functionalities that warrant deeper manual testing.")

class TurboIntruderScript(BaseModel):
    """Defines the expected JSON structure for a generated Turbo Intruder script."""
    script_code: str = Field(..., description="The Python script code for Turbo Intruder.")
    explanation: str = Field(..., description="An explanation of what the script does and how to use it.")
    suggested_payloads: List[str] = Field(default_factory=list, description="Examples of payloads that could be used with this script.")

class SecurityFinding(BaseModel):
    """Defines the structure for a single security finding."""
    title: str = Field(..., description="A concise, descriptive title for the finding.")
    severity: str = Field(..., description="The severity: Critical, High, Medium, Low, or Informational.")
    stage: str = Field(default="Recon/Analysis", description="Lifecycle/Testing stage (e.g. Reconnaissance, Input Validation, Auth).")
    owasp: str = Field(default="A01:2021", description="OWASP Top 10 category reference (e.g. A03:2021 - Injection).")
    mitre: str = Field(default="CWE-200", description="MITRE CWE identifier or ATT&CK technique.")
    confidence: str = Field(default="Confirmed", description="Confidence level: Confirmed or Potential.")
    exploitability: str = Field(default="Medium", description="Ease of exploitation: High, Medium, Low, or Theoretical.")
    description: str = Field(..., description="A clear, technical explanation of the vulnerability.")
    evidence: str = Field(default="", description="The specific quote, parameter, or header that proves the finding.")
    poc: str = Field(default="", description="Proof of concept steps, curl command, or attack vector payload.")
    impact: str = Field(default="", description="Potential business and technical impact if exploited.")
    next_steps: str = Field(default="", description="Immediate manual tests to confirm or dig deeper.")
    remediation: str = Field(default="", description="Actionable recommendations to fix the vulnerability.")

class SecurityAssessment(BaseModel):
    """Defines the overall structure for a security assessment of an HTTP pair."""
    executive_summary: str = Field(default="", description="Executive summary with strategic overview of the target security posture.")
    findings: List[SecurityFinding] = Field(default_factory=list, description="A list of security findings identified in the HTTP pair.")
    conclusion: str = Field(default="", description="Final security posture evaluation and next testing phase recommendations.")
