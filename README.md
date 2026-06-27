# Burp_Thinker (scaffold)

Arquitetura:
- Burp Extension (Jython/Java) <-> REST API (FastAPI)
- REST API é modular: Prompt Builder, Cache, Conversation Manager, Providers, Logging.


Baixar:
1. git clone https://github.com/orestescaminha/Burp_Thinker.git
2. cd Burp_Thinker

Execultar o server localmente:
3. copy .env.example to .env and set BURP_THINKER_TOKEN and provider API keys if usar providers
4. python -m venv .venv && source .venv/bin/activate
5. pip install -r server/requirements.txt
6. cd server && uvicorn app.main:app --host 127.0.0.1 --port 8000

Run extension:
- No Burp, configure Jython env, carregue burp_extension/BurpThinker.py
- A extensão faz requests para http://127.0.0.1:8000 com header Authorization Bearer <BURP_THINKER_TOKEN>

Como obter/definir o valor de BURP_THINKER_TOKEN
O token é só um segredo que o servidor usa para autorizar requisições. Pode ser qualquer string suficientemente forte. Exemplos práticos:

Gerar um token seguro (recomendado)
Unix/macOS: export BURP_THINKER_TOKEN=$(openssl rand -hex 32)
Alternativa (Python): export BURP_THINKER_TOKEN=$(python - <<'PY'\nimport secrets,sys\nprint(secrets.token_hex(32))\nPY)

Persistir em server/.env (opcional)
Edite server/.env (ou crie) e adicione: BURP_THINKER_TOKEN=seu_token_gerado_aqui
    Observação: o app atualmente apenas lê variáveis de ambiente; ele não carrega .env automaticamente — se quiser que .env seja lido automaticamente, instale python-dotenv e carregue no main.py, ou exporte a variável no terminal antes de iniciar uvicorn (recomendado para desenvolvimento).

Configure o provedor de sua preferência
Edite o valor de BURP_THINKER_PROVIDER em server/.env. Escolha "openai","claude", "gemini" ou "local"

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
