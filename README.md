# Burp_Thinker (scaffold)

Arquitetura:
- Burp Extension (Jython/Java) <-> REST API (FastAPI)
- REST API é modular: Prompt Builder, Cache, Conversation Manager, Providers, Logging.

Run server locally:
1. copy .env.example to .env and set BURP_THINKER_TOKEN and provider API keys if usar providers
2. python -m venv .venv && source .venv/bin/activate
3. pip install -r server/requirements.txt
4. cd server && uvicorn app.main:app --host 127.0.0.1 --port 8000

Run extension:
- No Burp, configure Jython env, carregue burp_extension/BurpThinker.py
- A extensão faz requests para http://127.0.0.1:8000 com header Authorization Bearer <BURP_THINKER_TOKEN>

Segurança:
- O servidor deve ser iniciado com host 127.0.0.1
- Tokens e chaves em variáveis de ambiente ou .env (não armazenar no Burp)
- Limite de tamanho para request/response (ex.: 64KB/128KB)

Endpoints principais:
- POST /analyze/request  { "request": "...raw HTTP..." }
- POST /analyze/response { "response": "...raw HTTP..." }
- POST /payloads/sqli    { "parameter": "id", "dbms": "mysql" }
- POST /jwt              { "token": "..." }
- GET  /tasks/{task_id}
