# Burp Thinker v2.3.4

![GitHub last commit](https://img.shields.io/github/last-commit/orestescaminha/Burp_Thinker)
![GitHub issues](https://img.shields.io/github/issues/orestescaminha/Burp_Thinker)
![GitHub stars](https://img.shields.io/github/stars/orestescaminha/Burp_Thinker)
![License](https://img.shields.io/github/license/orestescaminha/Burp_Thinker)

Burp Thinker is a Burp Suite extension designed to integrate Artificial Intelligence (AI) capabilities, specifically leveraging large language models (LLMs) like Google Gemini, directly into your web penetration testing workflow. It provides a context menu (`Right click -> Send to AI`) to send HTTP requests, responses, request and the corresponding response, or selected text to a local FastAPI server for AI-powered analysis and generation tasks.
The results, history, and details are displayed in a dedicated graphical interface within Burp (HTML) as well as in the extension console (JSON).

## Features

Burp Thinker enhances your Burp Suite experience with the following AI-powered functionalities:

*   **Analyze Request:** Get a security-focused summary and identify interesting parameters/vulnerabilities in HTTP requests.
*   **Analyze Response:** Obtain an analysis of HTTP responses, including reflected parameters, security headers, and potential info disclosure.
*   **Generate SQLi Payloads:** Generate SQL Injection payloads for specified parameters and database types.
*   **Generate XSS Payloads:** Generate diverse Cross-Site Scripting test vectors for various contexts.
*   **Explain CSP:** Analyze Content Security Policy (CSP) headers, explaining directives, weaknesses, and providing recommendations.
*   **Explain Stack Trace:** Get an explanation of stack traces, including root cause, potential vulnerabilities, and mitigation advice.
*   **Suggest Fuzzing Strategy:** Receive tailored fuzzing strategies based on HTTP request/response context.
*   **Summarize Crawl:** Summarize web application crawl data (e.g., list of URLs), identifying interesting points and technologies.
*   **Generate Turbo Intruder Script:** Generate Python scripts for Burp's Turbo Intruder based on a base HTTP request.
*   **Analyze Request/Response Pair:** Analyze an HTTP request and the corresponding response.

## Architecture Overview

The Burp Thinker project follows a modular, two-component architecture:

1.  **FastAPI Server (Python):** A local web server that exposes REST API endpoints. This server handles all AI interactions, caching, and business logic.
2.  **Burp Extension (Jython):** A Python script running within Burp Suite that acts as a client to the FastAPI server. It provides the context menu integration and sends data to the local API.

### Communication Flow

1.  **Burp (Jython) → FastAPI Server:** When a user triggers an action from the Burp context menu, the Jython extension sends a `POST` request to `http://127.0.0.1:8000/<endpoint>`.
    *   Requests include an `Authorization: Bearer local-secret` header and `Content-Type: application/json`.
    *   The extension runs these calls in a separate thread to prevent blocking the Burp Suite GUI.
2.  **FastAPI Server Processing:**
    *   The server receives the request and performs an `auth_check`.
    *   It calculates a SHA256 hash of the input data.
    *   **Cache Check:** If a cache hit occurs (same input, within TTL), the cached result is returned immediately.
    *   **AI Interaction:** If a cache miss, the request is forwarded to the `ConversationManager`.
    *   The `ConversationManager` uses the `ProviderFactory` to select the appropriate LLM provider (Gemini, OpenAI, etc.).
    *   A specific prompt is built (`Prompt Builder`) based on the action and input.
    *   The LLM API is called.
    *   The LLM's response is validated against a Pydantic schema (`schemas.py`) to ensure a structured JSON output.
    *   The validated result is saved to the cache.
    *   The result is returned to the Burp extension.
3.  **Asynchronous Operations:** For repetitive tasks (e.g., large crawls), an optional asynchronous mode (`X-Async` header) allows the client to get a `task_id` and poll `/tasks/{id}` for results.
4.  **Security & Limits:** The server listens only on `127.0.0.1`, reads API keys from environment variables (`.env`), and applies size limits to payloads.

### Core Components

*   **`server/app/main.py`**: The FastAPI application entry point. Handles environment variable loading (`.env`).
*   **`server/app/routes.py`**: Defines all API endpoints (`/analyze/request`, `/payloads/xss`, etc.), handles authentication, caching, and delegates to the `ConversationManager`.
*   **`server/app/conversation.py`**: Orchestrates the AI interaction. It selects the correct prompt, calls the LLM provider, and validates the LLM's JSON response against Pydantic schemas.
*   **`server/app/providers.py`**: Manages different LLM providers (Gemini, OpenAI, Anthropic, Local). Uses lazy initialization and attempts to import `google.genai` first, falling back to `google.generativeai` if necessary.
*   **`server/app/prompt_builder.py`**: Contains functions to construct detailed, locale-aware prompts for each AI action, guiding the LLM to produce structured JSON output.
*   **`server/app/schemas.py`**: Defines Pydantic models for the expected JSON structure of AI responses, enabling robust validation.
*   **`server/app/cache.py`**: Implements a simple SQLite-based cache (`burp_thinker_cache.sqlite`) to store AI responses, reducing redundant LLM calls.
*   **`burp_extension/BurpThinker.py`**: The Jython script for Burp Suite, handling context menu creation, data extraction from Burp, and asynchronous communication with the FastAPI server.

## Setup & Installation

### Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   `venv` (Python virtual environment)
*   Burp Suite (Community or Professional)
*   Jython standalone JAR (version 2.7.x recommended, `jython-standalone-2.7.4.jar`) Download the Jython standalone jar (https://www.jython.org/download). Place it somewhere safe and easy to access. I put mine in 'burp_extension' folder.

### 1. Clone the Repository

```bash
git clone https://github.com/orestescaminha/Burp_Thinker.git
cd Burp_Thinker
```

### 2. Configure Environment Variables

Create a `.env` file in the `server/` directory by copying the example:

```bash
cp server/.env.example server/.env
```

Edit `server/.env` and fill in the values:

```ini
BURP_THINKER_TOKEN=local-secret  # Keep this value for local testing
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
BURP_THINKER_PROVIDER=gemini     # Choose your preferred provider: openai|claude|gemini|local
GEMINI_MODEL=gemini-1.5-pro-latest # Or another Gemini model, e.g., gemini-1.5-flash
BURP_THINKER_CACHE_TTL=3600      # Optional: Cache TTL in seconds (default: 1 hour)
BURP_THINKER_LOCALE=en           # Optional: 'pt' for Portuguese, 'en' for English (default: pt)
```

**Important:** Ensure your `GEMINI_API_KEY` is correctly set if you choose `gemini` as your provider.

### 3. Create and Activate Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r server/requirements.txt
```

### 5. Start the FastAPI Server

Navigate to the `server` directory and start the Uvicorn server:

```bash
cd server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Note:** To ensure environment variables from `.env` are loaded correctly, it's best to stop and restart the server completely if you modify `.env`.

## Burp Suite Extension Setup

### 1. Load the Jython JAR

*   Open Burp Suite.
*   Go to `Extensions -> Installed`.
*   Click `Add`.
*   In the "Extension details" section, for "Python environment", point the "Location of Jython standalone JAR file" to:
    `path/to/Burp_Thinker/burp_extension/jython-standalone-2.7.4.jar`

### 2. Load the Burp Thinker Extension

*   In Burp Suite, go to `Extensions -> Installed`.
*   Click `Add`.
*   Set "Extension type" to `Python`.
*   Point the "Extension file" to:
    `path/to/Burp_Thinker/burp_extension/BurpThinker.py`
*   Click `Next`.

You should see `[*] Burp Thinker extension loaded successfully` in the Burp Extender output.

![HTML Output exemple](https://github.com/orestescaminha/Burp_Thinker/blob/main/docs/HTML_Output.png)
                                 *HTML Output example*


## Usage

1.  **Navigate** to the Proxy tab, Repeater, or any other tab displaying HTTP requests/responses.
2.  **Right-click** on an HTTP message (request or response) or select a specific text portion within it.
3.  In the context menu, go to `Extensions -> Burp Thinker`.
4.  Select the desired AI action (e.g., `Analyze Request`, `Generate XSS Payloads`, `Explain CSP`).
5.  The extension will send the relevant data to your local FastAPI server.
6.  In the Burp_Thinker tab, click the new row that appears in the history table. The details panel will display a nice, easy-to-read HTML preview
7.  The JSON AI's analysis or generated content will also be displayed in the Burp Extender output console.

**Example Output in Burp Extender Console:**

```
[*] Burp Thinker extension loaded successfully
[*] API URL: http://127.0.0.1:8000
[*] Token: ***
[*] Action triggered: analyze_request
[*] Selected 1 message(s)
[*] Data length for action 'analyze_request': 769 bytes
[*] Background task started for action: analyze_request
[*] Starting POST request...
[*] URL: http://127.0.0.1:8000/analyze/request
[*] Headers set
[*] Body prepared, size: 836 bytes
[*] Body sent
[*] Response code: 200
[+] Burp Thinker result (HTTP 200):
{"summary":"This is a very basic GET request...", "interesting_parameters":[], ...}
```

## Troubleshooting Common Issues
### Extensions console logs
Open the Burp Extensions Tab → Select Burp Thinker → Output
You will now see logs showing:
```
[*] Action triggered: analyze_request
[*] Selected X message(s)
[*] Raw message length: XXX bytes
[*] URL: http://127.0.0.1:8000/analyze/request
[*] Headers set
[*] Body sent
[*] Response code: 200/422/etc
[+] Burp Thinker result: {...}
Or [!] Burp Thinker error: ... with a traceback in case something goes wrong
```
### Common scenarios that logging can reveal:
*   `[!] No messages selected`: Ensure you have selected an HTTP message or text. For example: the `Explain Stack Trace` action requires selecting a snippet of text (a `stack trace`) within an HTTP request or response in Burp.
*   `[!] Connection refused`: Verify your FastAPI server is running at [http://127.0.0.1:8000](http://127.0.0.1:8000).
*   `[!] Response code: 401 Unauthorized`: Check your `BURP_THINKER_TOKEN` in `.env` and ensure it matches the extension's configuration.
*   `[!] Response code: 422 Unprocessable Content`: Indicates a validation error (e.g., missing required fields in the payload).
*   `[!] Burp Thinker error: ...`: Check the FastAPI server's console for detailed Python tracebacks.
*   `[!] Unterminated string starting at: line X column Y` error from `json.loads()` indicates that the AI ​​response was truncated in the middle of a string. This can happen when analyzing a request/response pair that requires parsing two blocks of text and generating a detailed JSON structure. This process consumes a large number of input tokens and produces a long response. Our current limit, configured in `providers.py`, is **8192** for the `GeminiProvider`. This value is the maximum supported by many models and should be more than sufficient for the most complex analyses.
*   `[!] ValueError: payload too large`: the file `server/app/routes.py` specifies the limit `check_size_limits(raw, max_kb=512)` on line 78. To resolve this, manually change that value.
*   `[!] Address already in use`: A process is already listening on port 8000 (likely a previous instance of uvicorn). Before restarting, kill the process using port 8000 or use a different port:
To list/terminate the process:
```bash
lsof -i :8000
kill <PID>
```
Or
```bash
pkill -f 'uvicorn'
```
Or start uvicorn on another port:
```bash
python -m uvicorn server.app.main:app --host 127.0.0.1 --port 8001 --reload
```
*   `[!] Connection refused`: server is not running on 127.0.0.1:8000 (start uvicorn)
*   `[!] Timeout`: Server slow or frozen
### Curl API Testing
cURL is a powerful command-line tool that allows for quick and direct interaction with APIs, making it ideal for testing and debugging.
Using the `curl` command is a quick and efficient way to test whether the authentication, validation, and parsing logic are correct.
A successful `curl` command confirms that your API and server are functioning perfectly.
When running `curl` command (with the uvicorn server running), you should receive a JSON response from the API containing an output, formatted according to the endpoit schema defined.
For the `curl` command using the `$BURP_THINKER_TOKEN` variable to work, you need to ensure the variable is exported in your shell (e.g., `export BURP_THINKER_TOKEN=local-secret; echo $BURP_THINKER_TOKEN`) or, if you prefer, insert the token value directly (without reading the .env file) into the `-H 'Authorization: Bearer local-secret'` header, as shown in the examples below:
```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/analyze/request' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer local-secret' \
  -H 'Content-Type: application/json' \
  -d '{
  "request": "GET / HTTP/1.1\r\nHost: example\r\n\r\n"
}'
```
Command explanation:
* -X 'POST': Sets the HTTP method to POST. 
* 'http://127.0.0.1:8000/analyze/request': The URL of the endpoint. 
* -H 'accept: application/json': Indicates that we expect a JSON response. 
* -H 'Authorization: Bearer local-secret': The required authentication header. 
* -H 'Content-Type: application/json': Indicates that the request body is JSON. 
* -d '{"request": "GET / HTTP/1.1\r\nHost: example\r\n\r\n"}': The request body, containing a JSON object with the key "request" and a value containing the request. "Host: example" in OpenAPI refers to the server's hostname where the API is hosted, i.e., uvicorn server
The bash script above tests the **Analyze Request** functionality; the structure is the same for testing other features. Though **Explain Stack Trace** and **Summarize Crawl** have slight nuances. Examples follow:
#### Explain Stack Trace
To test the "Explain Stack Trace" functionality using curl, you need to send a JSON object—formatted as a single line to avoid shell interpretation issues—containing the stack trace to the `/explain/stack_trace` endpoint.
Here is an example of how to do this using a simple Python stack trace.
```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/explain/stack_trace' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer local-secret' \
  -H 'Content-Type: application/json' \
  -d '{"stack_trace": "Traceback (most recent call last):\\n  File \"<stdin>\", line 1, in <module>\\nValueError: Invalid input for function"}'
```
**Notes:** 
* Note that I used `\\n` to ensure that `\n` is interpreted as a line break within the JSON string, and not as a shell escape character. 
* All -d JSON is enclosed in single quotes and on a single line. 
* Make sure the stack_trace is all on one line inside the JSON double quotes.
#### Summarize Crawl
In Burp, you need to select a text snippet (such as a list of URLs from a crawl) within an HTTP request or response and use the 'Summarize Crawl' option from the menu.
To test the "Summarize Crawl" functionality using curl, you must send a JSON payload containing the crawl data (for example, a list of URLs or a text-based sitemap) to the `/summarize/crawl` endpoint.
```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/summarize/crawl' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer local-secret' \
  -H 'Content-Type: application/json' \
  -d '{
  "crawl_data":"http://example.com/index.html\nhttp://example.com/about.html\nhttp://example.com/products?id=1\nhttp://example.com/admin/login.php\nhttp://example.com/api/v1/users"
}'
```
**Note:**
The request body, containing a JSON object with the key "crawl_data" and a value consisting of a string containing the crawl data (in this example, URLs separated by \n).
#### Validate JSON responses from endpoints using curl
You can pipe the curl response to a JSON validator like `jq` to capture the error body returned by FastAPI (it contains the exact reason).:
```
curl -s -X POST "http://127.0.0.1:8000/analyze/request" \
  -H "Authorization: Bearer local-secret" \
  -H "Content-Type: application/json" \
  -d '{"request": "GET / HTTP/1.1\r\nHost: example\r\n\r\n"}' | jq
```
## API Endpoints

The FastAPI server exposes the following main endpoints:

*   `POST /analyze/request`: Analyze an HTTP request.
*   `POST /analyze/response`: Analyze an HTTP response.
*   `POST /analyze/http_pair`: Analyze Request/Response Pair
*   `POST /payloads/sqli`: Generate SQLi payloads.
*   `POST /payloads/xss`: Generate XSS payloads.
*   `POST /explain/csp`: Explain a Content Security Policy header.
*   `POST /explain/stack_trace`: Explain a stack trace.
*   `POST /suggest/fuzzing_strategy`: Suggest a fuzzing strategy.
*   `POST /summarize/crawl`: Summarize crawl data.
*   `POST /generate/turbo_intruder_script`: Generate a Turbo Intruder script.
*   `POST /jwt`: Analyze a JWT token.
*   `GET /tasks/{task_id}`: Retrieve results for asynchronous tasks.
*   `GET /`: Redirects to `/static/` (simple frontend).
*   `GET /docs`: OpenAPI (Swagger UI) documentation.
*   `GET /redoc`: ReDoc documentation.

## Security & Best Practices

*   **API Keys:** Store all API keys in environment variables (e.g., `.env` file) and never hardcode them or commit them to version control.
*   **Local-only Binding:** The FastAPI server is configured to listen only on `127.0.0.1` by default, limiting its attack surface to the local machine.
*   **Authorization:** Uses a simple `Bearer` token (`local-secret` by default) for local authentication between the Burp extension and the server.
*   **Size Limits:** Payloads sent to the AI are subject to size limits (e.g., 64KB for requests, 512KB for responses) to prevent abuse and manage costs. These are configurable in `server/app/routes.py`.
*   **Cache:** AI responses are cached to reduce redundant LLM calls and improve performance.

## Future Enhancements

*   **Java Extension:** Implement the Burp extension in Java for better performance, tighter integration with Burp's API, and a more polished UI. The current Jython script serves as a functional Proof-of-Concept.
*   **More AI Actions:** Expand the range of AI-powered security testing actions.
*   **Configurable LLM Parameters:** Allow users to configure LLM parameters (temperature, top_p, etc.) via the UI or configuration file.
*   **Endpoint for Health Checks:** Add a simple `GET /health` endpoint for monitoring server status.

## Credits

**Orestes Q Caminha**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
