# 🧹 Slack Purge

Aplicação web para deletar mensagens do Slack de forma silenciosa. Cada usuário autoriza com sua conta e deleta apenas suas próprias mensagens.

## Features

- 🔕 **Silencioso** — usa User Token, ninguém é notificado
- 📅 **Filtro por data** — dia específico, range ou tudo
- 🧵 **Threads incluídas** — varre mensagens dentro de threads
- 🔍 **Dry Run** — simula antes de deletar
- 📊 **Progresso em tempo real** — acompanhe no dashboard
- 🐳 **Docker ready** — deploy fácil no Railway

## Setup

### 1. Configurar o Slack App

1. Acesse https://api.slack.com/apps e selecione seu app (ou crie um novo)
2. Em **OAuth & Permissions** → **User Token Scopes**, adicione:
   - `channels:history`, `channels:read`
   - `groups:history`, `groups:read`
   - `im:history`, `im:read`
   - `mpim:history`, `mpim:read`
   - `chat:write`
   - `users:read`
3. Em **OAuth & Permissions** → **Redirect URLs**, adicione:
   - Para local: `http://localhost:8080/auth/callback`
   - Para Railway: `https://seu-app.up.railway.app/auth/callback`
4. Em **Basic Information**, copie o **Client ID** e **Client Secret**

### 2. Variáveis de ambiente

```bash
cp .env.example .env
# Edite o .env com suas credenciais
```

### 3. Rodar localmente

```bash
docker compose up --build
# Acesse http://localhost:8080
```

### 4. Deploy no Railway

1. Crie um novo projeto no Railway
2. Conecte seu repositório GitHub (ou faça deploy via CLI)
3. Adicione as variáveis de ambiente:
   - `SLACK_CLIENT_ID`
   - `SLACK_CLIENT_SECRET`
   - `FLASK_SECRET_KEY` (gere com `python -c "import secrets; print(secrets.token_hex(32))"`)
4. Railway detecta o Dockerfile automaticamente
5. Depois do deploy, copie a URL e adicione como Redirect URL no Slack App:
   `https://seu-app.up.railway.app/auth/callback`

## Uso

1. Acesse a URL do app
2. Clique **"Autorizar com Slack"**
3. Confirme as permissões no Slack
4. No dashboard, escolha o período
5. Rode um **Dry Run** primeiro
6. Se ok, rode o purge de verdade

## Segurança

- Nenhum token é persistido em banco — apenas na sessão HTTP
- Cada usuário autoriza individualmente
- Só é possível deletar as próprias mensagens
- A sessão expira ao fechar o navegador

## Stack

- Python 3.12 + Flask
- Gunicorn (production)
- Docker / Docker Compose
- Zero dependências externas além do Flask
