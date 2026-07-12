# Burp_Thinker
O 'Burp_Thinker' é uma extensão para para integrar IA ao 'Burp Suite' e enviar requisições, atravez de um menu de contexto (Right click -> Send to AI).
Um servidor Python (FastAPI) implementa a arquitetura em camadas (Prompt Builder, Cache, Conversation Manager, OpenAI/Gemini/Anthropic/Local LLM Providers, Logging) e uma extensão Burp (Jython) que consome a API local de forma assíncrona e segura.
## Resumo direto:
- Servidor FastAPI com endpoints especializados (analisar request/response, gerar payloads SQLi, analisar JWT).
- Cache baseado em SHA256 (SQLite) para evitar chamadas repetidas.
- Suporte a providers (OpenAI/Gemini/Anthropic/Local LLM) por interface.
- Mecanismo opcional assíncrono (modo async via background task + task_id).
- Extensão Burp (Jython) que faz chamadas a localhost: Authorization Bearer local-secret, roda em thread para não bloquear GUI.
- Segurança: só escuta 127.0.0.1, leitura de API keys de env/.env.
  O provider deve Analyze Request, Analyze Response, Find Hidden Parameters, Generate SQLi Payloads, Generate XSS Payloads, Explain JWT, Explain CSP, Explain Stack Trace, Suggest Fuzzing Strategy, Summarize Crawl e Generate Turbo Intruder Script
## Explicação curta do fluxo:
- Burp (Jython) → POST localhost:8000/<endpoint> com Authorization Bearer local-secret e Content-Type.
- O server recebe, calcula SHA256(input) → se cache hit retorna imediatamente → se miss chama provider via Conversation Manager → salva no cache → retorna.
- Para operações repetitivas (fuzz, crawls) usa cache e endpoint async (X-Async header) para obter task_id e depois polling /tasks/{id}.
- Limites de tamanho e checagens são aplicadas.
      
## Arquitetura:
- Burp Extension (Jython/Java) <-> REST API (FastAPI)
- REST API é modular: Prompt Builder, Cache, Conversation Manager, Providers, Logging.

# Instalação:
## Clonar
```
git clone https://github.com/orestescaminha/Burp_Thinker.git
cd Burp_Thinker
```
## Criar .env
```
cp server/.env.example server/.env
```
## Configure variáveis de ambiente (no shell ou em server/.env)
### Editar `server/.env` e preencher chaves:
```
BURP_THINKER_TOKEN=local-secret (ou seu token)
BURP_THINKER_PROVIDER=openai|claude|gemini|local
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
GEMINI_API_KEY=...
```
### Exportar variáveis de ambiente
```
export BURP_THINKER_TOKEN=local-secret
export GEMINI_API_KEY=AIz.............lz1U
export BURP_THINKER_PROVIDER=gemini
export GEMINI_MODEL=gemini-2.5-flash
```

## Criar venv, instalar deps e rodar
```
python -m venv .venv
source .venv/bin/activate (PowerShell: .venv\Scripts\Activate.ps1)
pip install -r server/requirements.txt
cd server
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Observação: providers são tolerantes — se a SDK ou a API key não estiver presente, eles retornam uma resposta stub em vez de travar.


# Como Usar
    No Burp Suite:
        Vá para Extensions → Installed
        Clique Add (ou arrastar arquivo)
        Selecione burp_extension/BurpThinker.py
        Escolha Jython 2.7 (ou Jython nativo do Burp)
        Clique Next

    Teste a extensão:
        Vá para a aba Proxy ou qualquer outra que mostre requisições/respostas
        Clique com botão direito numa requisição/resposta
        Você verá duas opções de menu:
            "Send to AI -> Analyze Request"
            "Send to AI -> Analyze Response"
        Clique uma delas — a extensão enviará para o servidor local (127.0.0.1:8000) e exibirá o resultado no console de saída do Burp
        
    Veja o console — você verá logs tipo:
´´´    
    [*] Burp Thinker extension loaded successfully
    [*] API URL: http://127.0.0.1:8000
    [*] Token: ***
    [*] Action triggered: analyze_request
    [*] Selected 1 message(s)
    [*] Raw message length: 45 bytes
    [*] Background thread started for analysis
    [*] Starting POST request...
    [*] URL: http://127.0.0.1:8000/analyze/request
    [*] Headers set
    [*] Body prepared, size: 67 bytes
    [*] Body sent
    [*] Response code: 200
    [+] Burp Thinker result (HTTP 200):
    {"summary":"...","interesting_parameters":[...]}
´´´
Se houver erro:
´´´
    [!] No messages selected → nenhuma requisição/resposta selecionada
    [!] Connection refused → servidor (127.0.0.1:8000) não está rodando
    [!] Response code: 422 → erro de validação (payload/token inválido)
    [!] Response code: 401 → token incorreto
    Traceback completo vai aparecer no console
´´´
# Como testar localmente (passo a passo)
Testes usando uma solicitação GET básica. Normalmente é uma etapa inicial de reconhecimento para verificar se o servidor web está ativo e recuperar o conteúdo da página padrão, geralmente um arquivo index.
## Endpoints e exemplos curl

### 1. Analisar request (sincrono)

```
curl -X 'POST' \
  'http://127.0.0.1:8000/analyze/request' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer local-secret' \
  -H 'Content-Type: application/json' \
  -d '{
  "request": "GET / HTTP/1.1\r\nHost: example\r\n\r\n"
}'
```
#### Amostra da resposta esperada
```
{"summary":"A very basic HTTP GET request to the root path ('/') of the specified host. This request is minimal, with no query parameters or additional headers beyond the essential Host header, making it a foundational probe for server and application default behavior.","interesting_parameters":[],"possible_vulnerabilities":["Default file/page disclosure (e.g., index.html, default.php)","Directory listing vulnerability if the root path maps to a directory and directory listing is enabled on the server","Server information disclosure (e.g., server software and version in response headers or body)","Lack of proper redirection handling (e.g., to HTTPS or a canonical URL)","Vulnerabilities in the default web server configuration or the default application serving the root path"],"attack_surface":"The web server itself, the default application or files served at the root path ('/'), and the server's handling of generic, unauthenticated requests.","headers_of_interest":{"Host":"example"}}
```

### 2. Analisar response (sincrono) 
```
curl -X POST \
  "http://127.0.0.1:8000/analyze/response" \
  -H "Authorization: Bearer local-secret" \
  -H "Content-Type: application/json" \
  -d '{
  "response":"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>...</html>"
  }'
```
#### Amostra da resposta esperada
```
{"status_code":200,"interesting_headers":{"Content-Type":"text/html"},"cookies":[],"framework_detected":"None","potential_info_disclosure":[],"security_headers":{},"vulnerability_indicators":["Missing Strict-Transport-Security header (HSTS) - Allows downgrade attacks and cookie hijacking over insecure connections.","Missing X-Frame-Options header - Potential for Clickjacking attacks.","Missing X-Content-Type-Options header (nosniff) - Potential for MIME-sniffing attacks.","Missing Content-Security-Policy header (CSP) - Increased risk of Cross-Site Scripting (XSS) and other client-side injection attacks.","Missing Referrer-Policy header - Potential for sensitive information leakage through the Referer header.","Missing Permissions-Policy header - Lack of control over browser features that can be abused by malicious content."]}
```

### 3. Gerar payloads SQLi 
```
curl -s -X POST \
  "http://127.0.0.1:8000/payloads/sqli" \
  -H "Authorization: Bearer local-secret" \
  -H "Content-Type: application/json" \
  -d '{
  "parameter":"id","dbms":"mysql"
  }'
```
#### Amostra da resposta esperada
```
{"payloads":["'id' OR '1'='1'--","\" OR 1=1--","1; DROP TABLE users; --","' OR sleep(5)--"]}
```

### 4. Analisar JWT 
```
curl -s -X POST \
  "http://127.0.0.1:8000/jwt" \
  -H "Authorization: Bearer local-secret" \
  -H "Content-Type: application/json" \
  -d '{
  "token":"<JWT_HERE>"
  }'
```

### 5. Modo assíncrono (background tasks)
#### Request: 
```
curl -i -X POST \
  "http://127.0.0.1:8000/analyze/request" \
  -H "Authorization: Bearer local-secret" \
  -H "X-Async: 1" \
  -H "Content-Type: application/json" \
  -d '{
  "request":"..."
  }'
```
##### Amostra da resposta esperada
 -> retorna {"task_id":"..."} com 202

```
HTTP/1.1 200 OK
date: Sat, 11 Jul 2026 20:30:47 GMT
server: uvicorn
content-length: 56
content-type: application/json
[{"task_id":"d4a4705b-3805-402d-9453-bcf47ae739b2"},202]
```

#### Obter resultado: 
```
curl -s -X GET \
  "http://127.0.0.1:8000/tasks/{task_id}" \
  -H "Authorization: Bearer local-secret"
```
##### Amostra da resposta esperada
```
curl -s -X GET \
  "http://127.0.0.1:8000/tasks/{d4a4705b-3805-402d-9453-bcf47ae739b2}" \
  -H "Authorization: Bearer local-secret"
{"task_id":"d4a4705b-3805-402d-9453-bcf47ae739b2","status":"done","result":{"summary":"The provided HTTP request is empty, making a specific analysis impossible. The assessment is therefore based on general web application security principles rather than concrete request details.","interesting_parameters":[],"possible_vulnerabilities":["Lack of specific request details prevents identification of concrete vulnerabilities. However, common web application vulnerabilities like Injection (SQLi, XSS, Command), Broken Authentication, Sensitive Data Exposure, and Security Misconfigurations are always potential concerns in any web application.","Absence of request content means no parameters or headers could be analyzed for direct exploitation."],"attack_surface":"The attack surface cannot be precisely determined without an endpoint, method, or parameters. Generally, the attack surface would include all accessible endpoints, their input parameters, and HTTP headers used for communication with the the web server/application.","headers_of_interest":{}}} 
```

### 6. Usando jq
O comando abaixo mostra o JSON de validação
```
curl -s -X POST "http://127.0.0.1:8000/analyze/request" \
  -H "Authorization: Bearer local-secret" \
  -H "Content-Type: application/json" \
  -d '{"request": "GET / HTTP/1.1\r\nHost: example\r\n\r\n"}' | jq
{
  "summary": "This is a very basic GET request to the root path of the host. It's a common initial reconnaissance step to check if a web server is alive, identify its default page, and gather basic server information from the response headers or content.",
  "interesting_parameters": [],
  "possible_vulnerabilities": [
    "Information disclosure (e.g., server banners in response, default pages revealing technology stacks, directory listing if '/' is misconfigured).",                                                                                                         
    "Weak default configurations or credentials for the web server or any application hosted at the root.",
    "Outdated web server software or underlying operating system components.",
    "Misconfigured HTTP methods or insecure server settings.",
    "Absence of security headers in the server's response (e.g., X-Frame-Options, Content-Security-Policy), which could lead to client-side vulnerabilities."                                                                                                   
  ],
  "attack_surface": "The primary attack surface is the web server software itself (and its configuration) listening on 'example', as well as any application or content deployed at the root path '/'. This includes potential default pages, administration interfaces, or unpatched vulnerabilities in the server stack.",                                                                    
  "headers_of_interest": {
    "Host": "example"
  }
}
```

# Testando a GeminiClient diretamente (exemplo Python curto)

Execute o script `Test_GeminiClient.py` para verificar a integração com o `Gemini` (utils de debug). Execulte-o na raiz do `Burp_Thinker`, com `venv` ativado:
```
python -m Test_GeminiClient
```
##### Amostra da resposta esperada
```
{'result': "<module 'google.genai' from '/usr/lib/gemini-cli/Burp_Thinker/.venv/lib/python3.13/site-packages/google/genai/__init__.py'>", 'status': 'success', 'metadata': {'model': 'gemini-2.5-flash', 'prompt_tokens': 7, 'completion_tokens': 4}}
```
Se a SDK do Gemini não estiver instalada ou a chave não for encontrada, o módulo retorna stubs legíveis (não quebra a API).


---

# Cache
O cache usa SHA256(key) → SQLite. Repetir a mesma entrada (**mesmo raw + endpoint**) retornará um objeto com `"cached": true` e o resultado salvo, reduzindo chamadas para provedores.
O cache respeita BURP_THINKER_CACHE_TTL (segundos). Entradas mais antigas que o TTL são removidas no acesso e tratadas como miss.
## Limpar o cache.
Se desejar, pode-se remover o arquivo do banco de dados SQLite do cache. O servidor irá recriá-lo automaticamente, vazio, na próxima execução.
Para remover o arquivo de cache do SQLite para limpar resultados antigos execute o seguinte comando no seu terminal:
```
rm /Caminho_para_o_Burp_Thinker/server/burp_thinker_cache.sqlite
```
---
# Docker (opção)

Observação importante: o Dockerfile atual inicia uvicorn com `--host 127.0.0.1` (dentro do container). Se você quiser expor o container na porta do host, modifique o CMD para usar `--host 0.0.0.0` (e então rode `docker run -p 127.0.0.1:8000:8000 --env-file server/.env ...`). Fazer isso com mapeamento restrito a 127.0.0.1 mantém a superfície de ataque limitada ao host local.

---
# Burp extension (Jython)
- Arquivo: `burp_extension/BurpThinker.py`
- Por padrão `TOKEN = "local-secret"` (mantenha esse valor igual a BURP_THINKER_TOKEN do servidor)
- Instale Jython no Burp Extender (se necessário), carregue o script e a extensão fará POSTs ao servidor em background para não bloquear a GUI.
---

### Segurança:
- O servidor deve ser iniciado com host 127.0.0.1
- Tokens e chaves em variáveis de ambiente ou .env (não armazena no Burp)
- Limite de tamanho para request/response (ex.: 64KB/128KB)

### Endpoints principais:
- POST /analyze/request  { "request": "...raw HTTP..." }
- POST /analyze/response { "response": "...raw HTTP..." }
- POST /payloads/sqli    { "parameter": "id", "dbms": "mysql" }
- POST /jwt              { "token": "..." }
- GET  /tasks/{task_id}

---
# Segurança e boas práticas
- Inicie sempre o servidor atrelado a 127.0.0.1.
- Use Authorization: Bearer <token> e mantenha token no servidor e extensão coerentes.
- Limites de tamanho aplicados (64KB request, 128KB response), ajustáveis conforme necessidade.
---
# A Fazer:
- Para produção, implementar a extensão em Java para maior robustez e uma UI melhor; embora o Jython script seja um PoC funcional.
- Adcionar ações: Generate XSS Payloads, Explain CSP, Explain Stack Trace, Suggest Fuzzing Strategy, Summarize Crawl e Generate Turbo Intruder Script
- Adicionar um endpoint /health (simples GET → 200) para health checks.
- Incluir um pequeno CSS ou link para /static/style.css para deixar a UI mais apresentável.
- Adicionar i18n/prompt locale: BURP_THINKER_LOCALE env var (pt/en) e adaptar GeminiPromptBuilder a gerar prompts em pt/en conforme configuração.
---

