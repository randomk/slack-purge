import os
import json
import time
import threading
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode, parse_qs, urlparse
from flask import Flask, redirect, request, render_template, jsonify, session, url_for
from uuid import uuid4

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", uuid4().hex)

# ─── Slack Config ─────────────────────────────────────────────────────────────

SLACK_CLIENT_ID = os.environ.get("SLACK_CLIENT_ID", "")
SLACK_CLIENT_SECRET = os.environ.get("SLACK_CLIENT_SECRET", "")
SLACK_API_BASE = "https://slack.com/api"

USER_SCOPES = ",".join([
    "channels:history",
    "channels:read",
    "groups:history",
    "groups:read",
    "im:history",
    "im:read",
    "mpim:history",
    "mpim:read",
    "chat:write",
    "users:read",
])

# ─── In-memory job tracking ──────────────────────────────────────────────────

purge_jobs = {}  # job_id -> { status, progress, total, deleted, errors, log, ... }

RATE_LIMIT_DELETE = 1.2
RATE_LIMIT_FETCH = 0.3
BATCH_SIZE = 200


# ─── Slack API Helper ────────────────────────────────────────────────────────

def slack_request(method: str, token: str, params: dict = None, retries: int = 3) -> dict:
    url = f"{SLACK_API_BASE}/{method}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = urlencode(params).encode("utf-8") if params else None
    req = Request(url, data=data, headers=headers, method="POST")

    for attempt in range(retries):
        try:
            with urlopen(req) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                if not result.get("ok"):
                    error = result.get("error", "unknown")
                    if error == "ratelimited":
                        retry_after = int(resp.headers.get("Retry-After", 30))
                        time.sleep(retry_after)
                        continue
                    return {"ok": False, "error": error}
                return result
        except HTTPError as e:
            if e.code == 429:
                retry_after = int(e.headers.get("Retry-After", 30))
                time.sleep(retry_after)
                continue
            return {"ok": False, "error": str(e)}

    return {"ok": False, "error": "max_retries"}


def date_to_ts(date_str: str, end_of_day: bool = False) -> str:
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    if end_of_day:
        dt = dt + timedelta(days=1) - timedelta(seconds=1)
    return str(dt.timestamp())


# ─── OAuth Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    user = session.get("slack_user")
    return render_template("index.html", user=user, client_id=SLACK_CLIENT_ID)


@app.route("/auth/slack")
def auth_slack():
    """Inicia o OAuth flow com o Slack."""
    state = uuid4().hex
    session["oauth_state"] = state

    base_url = request.url_root.rstrip("/")
    redirect_uri = f"{base_url}/auth/callback"

    params = urlencode({
        "client_id": SLACK_CLIENT_ID,
        "user_scope": USER_SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
    })

    return redirect(f"https://slack.com/oauth/v2/authorize?{params}")


@app.route("/auth/callback")
def auth_callback():
    """Callback do OAuth do Slack."""
    error = request.args.get("error")
    if error:
        return render_template("error.html", message=f"Slack retornou erro: {error}"), 400

    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return render_template("error.html", message="Código de autorização ausente"), 400

    if state != session.get("oauth_state"):
        return render_template("error.html", message="State inválido — possível CSRF"), 400

    # Trocar code por token
    base_url = request.url_root.rstrip("/")
    redirect_uri = f"{base_url}/auth/callback"

    result = slack_request("oauth.v2.access", "", {
        "client_id": SLACK_CLIENT_ID,
        "client_secret": SLACK_CLIENT_SECRET,
        "code": code,
        "redirect_uri": redirect_uri,
    })

    if not result.get("ok"):
        return render_template("error.html",
                               message=f"Erro ao obter token: {result.get('error')}"), 400

    # Extrair user token e info
    authed_user = result.get("authed_user", {})
    user_token = authed_user.get("access_token", "")
    user_id = authed_user.get("id", "")

    if not user_token:
        return render_template("error.html", message="Token de usuário não retornado"), 400

    # Buscar info do usuário
    user_info = slack_request("users.info", user_token, {"user": user_id})
    user_name = "Usuário"
    user_avatar = ""
    if user_info.get("ok"):
        profile = user_info["user"].get("profile", {})
        user_name = profile.get("real_name", user_info["user"].get("name", "Usuário"))
        user_avatar = profile.get("image_72", "")

    # Salvar na sessão
    session["slack_token"] = user_token
    session["slack_user_id"] = user_id
    session["slack_user"] = {
        "id": user_id,
        "name": user_name,
        "avatar": user_avatar,
    }

    return redirect(url_for("dashboard"))


@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    user = session.get("slack_user")
    if not user:
        return redirect(url_for("index"))
    return render_template("dashboard.html", user=user)


# ─── API: Listar canais ──────────────────────────────────────────────────────

@app.route("/api/conversations")
def api_conversations():
    token = session.get("slack_token")
    if not token:
        return jsonify({"error": "Não autenticado"}), 401

    conversations = []
    type_labels = {
        "public_channel": "público",
        "private_channel": "privado",
        "mpim": "group-dm",
        "im": "dm",
    }

    for ch_type in ["public_channel", "private_channel", "mpim", "im"]:
        cursor = None
        while True:
            params = {"types": ch_type, "limit": 200}
            if cursor:
                params["cursor"] = cursor

            result = slack_request("conversations.list", token, params)
            if not result.get("ok"):
                break

            for ch in result.get("channels", []):
                name = ch.get("name")
                if not name:
                    # DM: resolver nome do usuário
                    dm_user_id = ch.get("user", "")
                    if dm_user_id:
                        user_info = slack_request("users.info", token, {"user": dm_user_id})
                        if user_info.get("ok"):
                            name = user_info["user"].get("real_name",
                                   user_info["user"].get("name", dm_user_id))
                        else:
                            name = dm_user_id
                    else:
                        name = ch["id"]

                conversations.append({
                    "id": ch["id"],
                    "name": name,
                    "type": type_labels.get(ch_type, ch_type),
                })

            cursor = result.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break

    return jsonify({"conversations": conversations})


# ─── API: Iniciar Purge ──────────────────────────────────────────────────────

@app.route("/api/purge", methods=["POST"])
def api_purge():
    token = session.get("slack_token")
    user_id = session.get("slack_user_id")
    if not token or not user_id:
        return jsonify({"error": "Não autenticado"}), 401

    data = request.json or {}
    mode = data.get("mode", "date")  # date | range | all
    date_val = data.get("date")
    start_val = data.get("start")
    end_val = data.get("end")
    dry_run = data.get("dry_run", True)
    channels = data.get("channels", [])  # lista de channel IDs, vazio = todos

    # Validar datas
    oldest, latest = None, None
    if mode == "date" and date_val:
        oldest = date_to_ts(date_val)
        latest = date_to_ts(date_val, end_of_day=True)
    elif mode == "range" and start_val and end_val:
        oldest = date_to_ts(start_val)
        latest = date_to_ts(end_val, end_of_day=True)
    elif mode != "all":
        return jsonify({"error": "Parâmetros de data inválidos"}), 400

    # Criar job
    job_id = uuid4().hex[:8]
    purge_jobs[job_id] = {
        "status": "running",
        "progress": 0,
        "total_conversations": 0,
        "current_conversation": "",
        "messages_found": 0,
        "messages_deleted": 0,
        "errors": 0,
        "dry_run": dry_run,
        "log": [],
        "started_at": datetime.now().isoformat(),
    }

    # Rodar em background
    thread = threading.Thread(
        target=run_purge,
        args=(job_id, token, user_id, oldest, latest, dry_run, channels),
        daemon=True,
    )
    thread.start()

    return jsonify({"job_id": job_id})


def run_purge(job_id: str, token: str, user_id: str,
              oldest: str, latest: str, dry_run: bool, filter_channels: list):
    """Executa o purge em background."""
    job = purge_jobs[job_id]

    try:
        # 1. Buscar conversas
        add_log(job, "📡 Buscando conversas...")
        conversations = []

        for ch_type in ["public_channel", "private_channel", "mpim", "im"]:
            cursor = None
            while True:
                params = {"types": ch_type, "limit": 200}
                if cursor:
                    params["cursor"] = cursor
                result = slack_request("conversations.list", token, params)
                if not result.get("ok"):
                    break
                for ch in result.get("channels", []):
                    conversations.append({
                        "id": ch["id"],
                        "name": ch.get("name") or f"DM-{ch.get('user', ch['id'])}",
                        "type": ch_type,
                    })
                cursor = result.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break

        # Filtrar canais se especificado
        if filter_channels:
            conversations = [c for c in conversations if c["id"] in filter_channels]

        job["total_conversations"] = len(conversations)
        add_log(job, f"📋 {len(conversations)} conversas para varrer")

        # 2. Varrer cada conversa
        for i, conv in enumerate(conversations):
            ch_id = conv["id"]
            ch_name = conv["name"]
            job["progress"] = i + 1
            job["current_conversation"] = ch_name

            # Buscar mensagens do usuário
            messages = fetch_user_messages_api(token, ch_id, user_id, oldest, latest)

            if not messages:
                continue

            add_log(job, f"{'🔍' if dry_run else '🗑️'} {ch_name}: {len(messages)} mensagens")
            job["messages_found"] += len(messages)

            # Deletar
            for msg in messages:
                ts = msg["ts"]
                text = (msg.get("text") or "")[:60].replace("\n", " ")
                msg_time = datetime.fromtimestamp(float(ts)).strftime("%H:%M")
                thread_tag = " ↩" if msg.get("is_thread_reply") else ""

                if dry_run:
                    job["messages_deleted"] += 1
                    add_log(job, f"  👀 [{msg_time}]{thread_tag} {text}")
                    continue

                result = slack_request("chat.delete", token, {"channel": ch_id, "ts": ts})
                if result.get("ok"):
                    job["messages_deleted"] += 1
                    add_log(job, f"  ✅ [{msg_time}]{thread_tag} {text}")
                else:
                    job["errors"] += 1
                    add_log(job, f"  ❌ {result.get('error', '?')} [{msg_time}] {text}")

                time.sleep(RATE_LIMIT_DELETE)

        # Concluído
        job["status"] = "completed"
        mode_label = "DRY RUN" if dry_run else "PURGE"
        add_log(job, f"✅ {mode_label} concluído: {job['messages_deleted']} mensagens "
                      f"{'encontradas' if dry_run else 'deletadas'}, {job['errors']} erros")

    except Exception as e:
        job["status"] = "error"
        add_log(job, f"💥 Erro fatal: {str(e)}")


def fetch_user_messages_api(token: str, channel_id: str, user_id: str,
                            oldest: str = None, latest: str = None) -> list:
    """Busca mensagens do usuário no canal + threads."""
    user_messages = []
    thread_parents = set()
    seen_ts = set()
    cursor = None

    # Mensagens do canal
    while True:
        params = {"channel": channel_id, "limit": BATCH_SIZE}
        if oldest:
            params["oldest"] = oldest
        if latest:
            params["latest"] = latest
            params["inclusive"] = "true"
        if cursor:
            params["cursor"] = cursor

        result = slack_request("conversations.history", token, params)
        if not result.get("ok"):
            return []

        for msg in result.get("messages", []):
            ts = msg.get("ts", "")

            if msg.get("reply_count", 0) > 0:
                thread_parents.add(ts)
            if msg.get("thread_ts") and msg["thread_ts"] != ts:
                thread_parents.add(msg["thread_ts"])

            if msg.get("user") == user_id and ts not in seen_ts:
                subtype = msg.get("subtype", "")
                if subtype in ("channel_join", "channel_leave", "channel_topic",
                               "channel_purpose", "bot_message"):
                    continue
                seen_ts.add(ts)
                user_messages.append({
                    "ts": ts,
                    "text": (msg.get("text") or "")[:100],
                    "thread_ts": msg.get("thread_ts"),
                    "is_thread_reply": (msg.get("thread_ts") is not None
                                        and msg.get("thread_ts") != ts),
                })

        cursor = result.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
        time.sleep(RATE_LIMIT_FETCH)

    # Threads
    for thread_ts in thread_parents:
        thread_cursor = None
        while True:
            params = {"channel": channel_id, "ts": thread_ts, "limit": BATCH_SIZE}
            if thread_cursor:
                params["cursor"] = thread_cursor

            result = slack_request("conversations.replies", token, params)
            if not result.get("ok"):
                break

            for msg in result.get("messages", []):
                ts = msg.get("ts", "")
                if ts == thread_ts or ts in seen_ts:
                    continue
                if msg.get("user") != user_id:
                    continue
                if oldest and float(ts) < float(oldest):
                    continue
                if latest and float(ts) > float(latest):
                    continue

                seen_ts.add(ts)
                user_messages.append({
                    "ts": ts,
                    "text": (msg.get("text") or "")[:100],
                    "thread_ts": thread_ts,
                    "is_thread_reply": True,
                })

            thread_cursor = result.get("response_metadata", {}).get("next_cursor")
            if not thread_cursor:
                break
            time.sleep(RATE_LIMIT_FETCH)

    return user_messages


def add_log(job: dict, message: str):
    """Adiciona entrada ao log do job."""
    job["log"].append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "message": message,
    })
    # Manter últimas 500 entradas
    if len(job["log"]) > 500:
        job["log"] = job["log"][-500:]


# ─── API: Status do job ──────────────────────────────────────────────────────

@app.route("/api/purge/<job_id>")
def api_purge_status(job_id):
    job = purge_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job não encontrado"}), 404

    last_n = request.args.get("last_log", 50, type=int)

    return jsonify({
        "status": job["status"],
        "progress": job["progress"],
        "total_conversations": job["total_conversations"],
        "current_conversation": job["current_conversation"],
        "messages_found": job["messages_found"],
        "messages_deleted": job["messages_deleted"],
        "errors": job["errors"],
        "dry_run": job["dry_run"],
        "log": job["log"][-last_n:],
    })


# ─── Health check ────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
