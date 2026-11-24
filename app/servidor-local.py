import argparse
import base64
import binascii
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import sqlite3
import struct
from threading import Lock
import time
from urllib.parse import urlsplit

FILES = Path(__file__).resolve().parent
STATE = FILES.parent / "work" / "painel-local"
DB = STATE / "respostas.sqlite3"
SETUP_KEY = STATE / "configuracao.txt"
FORM = FILES / "seu-jeito-de-ser.html"
PANEL = FILES / "painel-natalia.html"
COOKIE = "natalia_session"
SESSION_TTL = 8 * 60 * 60
MAX_BODY = 256 * 1024
LOGIN_WINDOW = 60
LOGIN_LIMIT = 8
ATTEMPTS = {"login": [], "setup": []}
ATTEMPTS_LOCK = Lock()
ADMIN_LOCK = Lock()


class ApiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message


def connect():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    STATE.mkdir(parents=True, exist_ok=True)
    with closing(connect()) as db, db:
        db.executescript("""
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS responses (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                received_at TEXT NOT NULL,
                answers TEXT NOT NULL,
                signature BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS responses_received ON responses(received_at);
        """)
        if db.execute("SELECT 1 FROM admin").fetchone():
            SETUP_KEY.unlink(missing_ok=True)
        elif not SETUP_KEY.exists():
            SETUP_KEY.write_text(secrets.token_urlsafe(26), encoding="ascii")


def hash_password(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def limit_attempts(action):
    now = time.monotonic()
    with ATTEMPTS_LOCK:
        attempts = ATTEMPTS[action]
        attempts[:] = [stamp for stamp in attempts if now - stamp < LOGIN_WINDOW]
        if len(attempts) >= LOGIN_LIMIT:
            raise ApiError(429, "Muitas tentativas. Aguarde um minuto e tente novamente.")
        attempts.append(now)


def question_data():
    html = FORM.read_text(encoding="utf-8")
    match = re.search(r'<script type="application/json" id="question-data">(.*?)</script>', html, re.S)
    return json.loads(match[1])


def decode_signature(value):
    prefix = "data:image/png;base64,"
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ApiError(422, "Assine na tela antes de enviar.")
    try:
        data = base64.b64decode(value[len(prefix):], validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(422, "A assinatura está em um formato inválido.") from None
    if (len(data) < 33 or len(data) > 170_000 or data[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
            or struct.unpack(">II", data[16:24]) != (960, 340)):
        raise ApiError(422, "Refaça a assinatura na tela antes de enviar.")
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "NataliaLocal"

    def serve(self, status, body=b"", mime="application/json; charset=utf-8", cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def json(self, status, value, cookie=None):
        self.serve(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), cookie=cookie)

    def html(self, path):
        self.serve(200, path.read_bytes(), "text/html; charset=utf-8")

    def payload(self):
        if self.headers.get_content_type() != "application/json":
            raise ApiError(415, "Formato de envio inválido.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ApiError(413, "O arquivo enviado está fora do limite de tamanho.")
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError):
            raise ApiError(400, "Dados de envio inválidos.") from None
        if not isinstance(data, dict):
            raise ApiError(400, "Dados de envio inválidos.")
        return data

    def session(self, db):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        value = cookies.get(COOKIE)
        if not value or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value.value):
            return None
        digest = token_hash(value.value)
        return digest if db.execute(
            "SELECT 1 FROM sessions WHERE token_hash = ? AND expires > ?", (digest, int(time.time()))
        ).fetchone() else None

    def new_session(self, db):
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + SESSION_TTL
        db.execute("DELETE FROM sessions WHERE expires <= ?", (int(time.time()),))
        db.execute("INSERT INTO sessions VALUES (?, ?)", (token_hash(token), expires))
        return f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age={SESSION_TTL}"

    def route(self, method):
        host = self.headers.get("Host", "")
        if host not in self.server.allowed_hosts:
            raise ApiError(403, "Use o endereço local do servidor.")
        path = urlsplit(self.path).path
        if method == "POST" and self.headers.get("Origin") != f"http://{host}":
            raise ApiError(403, "Origem do envio inválida.")
        if method == "GET":
            if path in ("/", "/seu-jeito-de-ser.html"):
                return self.html(FORM)
            if path in ("/admin", "/admin/"):
                return self.html(PANEL)
            if path == "/api/status":
                return self.json(200, {"receivesResponses": True})
        if method == "POST" and path == "/api/responses":
            return self.submit()
        if path.startswith("/api/admin/"):
            return self.admin(method, path)
        raise ApiError(404, "Página não encontrada.")

    def handle_method(self, method):
        try:
            return self.route(method)
        except ApiError as error:
            return self.json(error.status, {"error": error.message})
        except (ConnectionResetError, BrokenPipeError):
            return
        except Exception as error:
            self.log_error("Erro interno em %s: %s", method, type(error).__name__)
            return self.json(500, {"error": "O servidor não conseguiu concluir a operação."})

    def do_GET(self):
        self.handle_method("GET")

    def do_POST(self):
        self.handle_method("POST")

    def submit(self):
        data = self.payload()
        name = data.get("name")
        rid = data.get("id")
        selected = data.get("selected")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or not name.isprintable():
            raise ApiError(422, "Informe um nome válido.")
        if not isinstance(rid, str) or not re.fullmatch(r"[a-f0-9-]{36}", rid):
            raise ApiError(422, "Identificador de envio inválido.")
        if not isinstance(selected, list) or not 1 <= len(selected) <= 32 or any(not isinstance(key, str) for key in selected):
            raise ApiError(422, "Marque pelo menos uma frase.")
        questions = {
            f"{round_index}-{index}": {"profile": profile, "text": text}
            for round_index, round_data in enumerate(question_data())
            for index, (profile, text) in enumerate(round_data["traits"])
        }
        selected_set = set(selected)
        if len(selected_set) != len(selected) or not selected_set.issubset(questions):
            raise ApiError(422, "Uma das respostas enviadas é inválida.")
        answers = json.dumps([answer for key, answer in questions.items() if key in selected_set], ensure_ascii=False)
        signature = decode_signature(data.get("signature"))
        name = name.strip()
        with closing(connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT name, answers, signature FROM responses WHERE id = ?", (rid,)).fetchone()
            if previous:
                if tuple(previous) != (name, answers, signature):
                    raise ApiError(409, "Este envio já foi recebido. Abra o teste novamente para enviar outra resposta.")
            else:
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                db.execute("INSERT INTO responses VALUES (?, ?, ?, ?, ?)", (rid, name, now, answers, signature))
        return self.json(200 if previous else 201, {"id": rid})

    def admin(self, method, path):
        with closing(connect()) as db:
            if method == "GET" and path == "/api/admin/status":
                return self.json(200, {
                    "configured": bool(db.execute("SELECT 1 FROM admin").fetchone()),
                    "authenticated": bool(self.session(db))
                })
            if method == "POST" and path in ("/api/admin/setup", "/api/admin/login"):
                return self.authenticate(db, path.rsplit("/", 1)[-1])
            session = self.session(db)
            if not session:
                raise ApiError(401, "Entre no painel para continuar.")
            if method == "POST" and path == "/api/admin/logout":
                with db:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (session,))
                return self.json(200, {}, f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=0")
            if method == "GET" and path == "/api/admin/responses":
                rows = db.execute("SELECT id, name, received_at FROM responses ORDER BY received_at DESC, rowid DESC")
                return self.json(200, [dict(row) for row in rows])
            if method == "GET":
                match = re.fullmatch(r"/api/admin/responses/([a-f0-9-]{36})(/signature)?", path)
                if match:
                    rid, signature = match.groups()
                    if signature:
                        row = db.execute("SELECT signature FROM responses WHERE id = ?", (rid,)).fetchone()
                        if row:
                            return self.serve(200, row["signature"], "image/png")
                    else:
                        row = db.execute("SELECT id, name, received_at, answers FROM responses WHERE id = ?", (rid,)).fetchone()
                        if row:
                            return self.json(200, {**dict(row), "answers": json.loads(row["answers"])})
            raise ApiError(404, "Resposta não encontrada.")

    def authenticate(self, db, action):
        limit_attempts(action)
        data = self.payload()
        password = data.get("password")
        if not isinstance(password, str) or not 1 <= len(password) <= 128:
            raise ApiError(422, "Informe uma senha válida.")
        if action == "setup":
            if len(password) < 12:
                raise ApiError(422, "Use pelo menos 12 caracteres na senha.")
            code = data.get("code")
            with ADMIN_LOCK:
                if db.execute("SELECT 1 FROM admin").fetchone():
                    raise ApiError(409, "O painel já foi configurado.")
                if not isinstance(code, str) or not code.isascii() or not secrets.compare_digest(code, SETUP_KEY.read_text(encoding="ascii")):
                    raise ApiError(403, "O código de configuração é inválido.")
                salt = secrets.token_bytes(16)
                with db:
                    db.execute("INSERT INTO admin VALUES (1, ?, ?)", (salt, hash_password(password, salt)))
                    cookie = self.new_session(db)
                SETUP_KEY.unlink(missing_ok=True)
        else:
            row = db.execute("SELECT salt, password_hash FROM admin").fetchone()
            if not row or not secrets.compare_digest(row["password_hash"], hash_password(password, row["salt"])):
                raise ApiError(401, "Senha incorreta.")
            with db:
                cookie = self.new_session(db)
        return self.json(200, {"authenticated": True}, cookie)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Servidor local do teste de temperamentos.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--state-dir", type=Path, default=STATE)
    args = parser.parse_args()
    STATE = args.state_dir.resolve()
    DB = STATE / "respostas.sqlite3"
    SETUP_KEY = STATE / "configuracao.txt"
    initialize()
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.allowed_hosts = (f"127.0.0.1:{args.port}", f"localhost:{args.port}")
        print(f"Teste em http://127.0.0.1:{args.port}/ e painel em /admin", flush=True)
        server.serve_forever()
