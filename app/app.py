import os, sqlite3, time, hashlib, secrets, threading
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse, urljoin
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory,
    abort,
    g,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from . import config
except ImportError:  # pragma: no cover - fallback for script execution
    import config

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
app.config["SITE_DOMAIN"] = getattr(config, "SITE_DOMAIN", None)
app.config["SITE_TAGLINE"] = getattr(config, "SITE_TAGLINE", None)
app.permanent_session_lifetime = timedelta(hours=6)


@app.context_processor
def inject_site_branding():
    """Expose site-wide branding details to every template."""

    domain = app.config.get("SITE_DOMAIN")
    if not domain:
        host = request.host or ""
        if host:
            domain = host.split(":", 1)[0]
        else:
            try:
                domain = urlparse(request.url_root).hostname
            except Exception:  # pragma: no cover - defensive fallback
                domain = None
    domain = domain or "File Server"
    return {
        "site_domain": domain,
        "site_tagline": app.config.get("SITE_TAGLINE"),
        "is_authenticated": bool(session.get("user_id")),
    }


def _format_size(num_bytes) -> str:
    """Return a human readable file size string.

    Uses powers of two (KiB, MiB, …) while keeping the output concise.
    Negative or non-numeric values gracefully fall back to ``0 B``.
    """

    try:
        value = float(num_bytes)
    except (TypeError, ValueError):
        return "0 B"

    if value < 0:
        value = 0.0

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            precision = 0 if value >= 100 else 1 if value >= 10 else 2
            text = f"{value:.{precision}f}"
            if "." in text:
                text = text.rstrip("0").rstrip(".")
            return f"{text} {unit}"
        value /= 1024.0
    return "0 B"


@app.template_filter("filesize")
def filesize_filter(num_bytes):
    return _format_size(num_bytes)

# Determine a writable location for the SQLite database. Allow overrides via
# the FILE_SERVER_DB_PATH environment variable and, by default, place the database in
# a hidden directory within the project root. Relying on the user's home
# directory caused mismatches when the administrative scripts were executed
# outside the server's environment, resulting in separate databases and failed
# logins. Using a path relative to the application keeps both the server and
# management scripts in sync while still permitting customization via the
# environment.
DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent / ".mini-data"
DB_PATH = Path(os.environ.get("FILE_SERVER_DB_PATH", DEFAULT_DB_DIR / "app.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
UPLOAD_ROOT = Path(config.UPLOAD_ROOT)
ALLOWED_EXTS = config.ALLOWED_EXTS
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB chunks provide a balance for retries
# Large uploads were timing out during finalisation because the server would
# re-read the entire file using tiny 8 KiB blocks to compute the checksum.  A
# 1+ GiB upload therefore spent tens of seconds hashing, long enough for
# Gunicorn's 30 second worker timeout to kill the request.  Using larger blocks
# keeps the hashing step fast while still avoiding excessive memory usage.
HASH_READ_SIZE = 4 * 1024 * 1024  # 4 MiB chunks for post-upload hashing
# Likewise, copy uploaded files from Werkzeug's stream to disk using larger
# blocks to minimise Python loop overhead.
STREAM_COPY_CHUNK_SIZE = 4 * 1024 * 1024
SHA1_PLACEHOLDER = "pending"

# Track failed login attempts per IP to implement a lightweight
# fail2ban-style ban mechanism that avoids inconveniencing legitimate users.
FAILED_LOGINS = {}
FAIL_LIMIT = 5
FAIL_WINDOW = 5 * 60  # seconds
BAN_SECONDS = 15 * 60


def _schedule_sha1_update(user_id: int, stored_name: str, file_id: int) -> None:
    """Hash ``stored_name`` asynchronously and store the digest in the database."""

    if not user_id or not stored_name or not file_id:
        return

    def worker():
        try:
            base_dir = (UPLOAD_ROOT / str(user_id)).resolve()
            target = (base_dir / stored_name).resolve()
            if not str(target).startswith(str(base_dir)) or not target.is_file():
                return
            sha1 = hashlib.sha1()
            with open(target, "rb") as fh:
                for block in iter(lambda: fh.read(HASH_READ_SIZE), b""):
                    if not block:
                        break
                    sha1.update(block)
            digest = sha1.hexdigest()
            with get_db() as db:
                db.execute("UPDATE files SET sha1=? WHERE id=?", (digest, file_id))
        except Exception:  # pragma: no cover - defensive logging for unexpected failures
            app.logger.exception(
                "Failed to compute SHA-1 for uploaded file",
                extra={"file_id": file_id, "user_id": user_id},
            )

    thread = threading.Thread(
        target=worker,
        name=f"sha1-{file_id}",
        daemon=True,
    )
    thread.start()


def _register_existing_file(user_id: int, stored_name: str, original_name: str = None) -> bool:
    """Ensure ``stored_name`` for ``user_id`` is represented in the database.

    Returns ``True`` when the file exists on disk and either already has a
    database record or one was created.  ``False`` indicates the file could not
    be verified.
    """

    if not user_id or not stored_name:
        return False

    base_dir = (UPLOAD_ROOT / str(user_id)).resolve()
    target = (base_dir / stored_name).resolve()

    if not str(target).startswith(str(base_dir)) or not target.is_file():
        return False

    try:
        stat = target.stat()
    except OSError:
        return False

    with get_db() as db:
        row = db.execute(
            "SELECT id, sha1 FROM files WHERE user_id=? AND stored_name=?",
            (user_id, stored_name),
        ).fetchone()
        if row:
            if row["sha1"] == SHA1_PLACEHOLDER:
                _schedule_sha1_update(user_id, stored_name, row["id"])
            return True

        uploaded_at = int(stat.st_mtime)
        if uploaded_at <= 0:
            uploaded_at = int(time.time())

        cursor = db.execute(
            "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token) VALUES(?,?,?,?,?,?,?)",
            (
                user_id,
                stored_name,
                original_name or stored_name,
                stat.st_size,
                uploaded_at,
                SHA1_PLACEHOLDER,
                secrets.token_urlsafe(8),
            ),
        )

    file_id = cursor.lastrowid if cursor else None
    _schedule_sha1_update(user_id, stored_name, file_id)
    return True


def _reconcile_user_files(user_id: int) -> None:
    """Create database records for orphaned files in the user's directory."""

    if not user_id:
        return

    base_dir = (UPLOAD_ROOT / str(user_id)).resolve()
    if not base_dir.exists():
        return

    try:
        with get_db() as db:
            rows = db.execute(
                "SELECT id, stored_name, sha1 FROM files WHERE user_id=?",
                (user_id,),
            ).fetchall()
    except sqlite3.Error:
        return

    known = {row["stored_name"]: row for row in rows}

    for path in base_dir.iterdir():
        if not path.is_file() or path.name.endswith(".part"):
            continue
        entry = known.get(path.name)
        if entry:
            if entry["sha1"] == SHA1_PLACEHOLDER:
                _schedule_sha1_update(user_id, path.name, entry["id"])
            continue
        _register_existing_file(user_id, path.name)


def _get_client_ip() -> str:
    """Return the best-effort client IP address for the current request."""

    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        candidate = forwarded_for.split(",", 1)[0].strip()
        if candidate:
            return candidate

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        candidate = real_ip.strip()
        if candidate:
            return candidate

    ip = request.remote_addr
    if isinstance(ip, str):
        ip = ip.strip()
        if ip:
            return ip
    return "unknown"


def _should_increment_counter(db, file_id: int, event: str) -> bool:
    """Record the first ``event`` from the current IP for ``file_id``.

    Returns ``True`` when the event is new and the caller should increment the
    corresponding aggregate counter.
    """

    if not file_id or event not in {"view", "download"}:
        return False

    ip = _get_client_ip()
    if not ip:
        return False

    timestamp = int(time.time())
    column = "first_viewed" if event == "view" else "first_downloaded"

    row = db.execute(
        "SELECT first_viewed, first_downloaded FROM file_accesses WHERE file_id=? AND ip=?",
        (file_id, ip),
    ).fetchone()

    if not row:
        first_viewed = timestamp if event == "view" else None
        first_downloaded = timestamp if event == "download" else None
        db.execute(
            "INSERT INTO file_accesses(file_id, ip, first_viewed, first_downloaded) VALUES(?,?,?,?)",
            (file_id, ip, first_viewed, first_downloaded),
        )
        return True

    if row[column] is None:
        db.execute(
            f"UPDATE file_accesses SET {column}=? WHERE file_id=? AND ip=?",
            (timestamp, file_id, ip),
        )
        return True

    return False


def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              can_upload INTEGER NOT NULL DEFAULT 0,
              must_change_password INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cols = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "must_change_password" not in cols:
            db.execute(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
            )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS files(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              stored_name TEXT NOT NULL,
              original_name TEXT NOT NULL,
              size INTEGER NOT NULL,
              uploaded_at INTEGER NOT NULL,
              downloads INTEGER NOT NULL DEFAULT 0,
              views INTEGER NOT NULL DEFAULT 0,
              sha1 TEXT NOT NULL,
              token TEXT NOT NULL UNIQUE,
              is_public INTEGER NOT NULL DEFAULT 1,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        cols = {row[1] for row in db.execute("PRAGMA table_info(files)")}
        if "is_public" not in cols:
            db.execute(
                "ALTER TABLE files ADD COLUMN is_public INTEGER NOT NULL DEFAULT 1",
            )
        if "token" not in cols:
            db.execute("ALTER TABLE files ADD COLUMN token TEXT")
            rows = db.execute("SELECT id FROM files WHERE token IS NULL").fetchall()
            for row in rows:
                db.execute(
                    "UPDATE files SET token=? WHERE id=?",
                    (secrets.token_urlsafe(8), row["id"]),
                )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS file_accesses(
              file_id INTEGER NOT NULL,
              ip TEXT NOT NULL,
              first_viewed INTEGER,
              first_downloaded INTEGER,
              PRIMARY KEY(file_id, ip),
              FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS upload_sessions(
              token TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL,
              stored_name TEXT NOT NULL,
              original_name TEXT NOT NULL,
              size INTEGER NOT NULL,
              chunk_size INTEGER NOT NULL,
              uploaded_bytes INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL,
              completed INTEGER NOT NULL DEFAULT 0,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        cols = {row[1] for row in db.execute("PRAGMA table_info(upload_sessions)")}
        if "completed" not in cols:
            db.execute(
                "ALTER TABLE upload_sessions ADD COLUMN completed INTEGER NOT NULL DEFAULT 0"
            )

# Ensure the database schema exists whenever the application is
# imported (e.g., under a WSGI server such as Gunicorn).  Previously,
# the tables were only created when running `app.py` directly, which
# meant workers launched by Gunicorn lacked the required `users` table
# and login attempts failed with "no such table: users".
init_db()

def is_safe_url(target):
    host_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target or ""))
    return (test_url.scheme in ("http","https")) and (host_url.netloc == test_url.netloc)

def user_dir():
    uid = session.get("user_id")
    if not uid:
        abort(401)
    d = UPLOAD_ROOT / str(uid)
    d.mkdir(parents=True, exist_ok=True)
    return d

def allowed_file(name: str) -> bool:
    if "." not in name:
        return False
    if ALLOWED_EXTS is None:
        return True
    ext = name.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_EXTS


def display_name(raw_name: str, fallback: str) -> str:
    """Return a user-facing file name derived from ``raw_name``.

    Browsers occasionally include path information (for example,
    ``C:\\fakepath\\report.txt``) or forward slashes. Trim everything except the
    final component so the dashboard shows the exact filename the user
    expects.  If nothing usable remains fall back to ``fallback`` which is the
    sanitized name written to disk.
    """

    candidate = (raw_name or "").strip()
    if not candidate:
        return fallback
    cleaned = candidate.replace("\\", "/").split("/")[-1].strip()
    return cleaned or fallback


def client_ip():
    return _get_client_ip()


def is_banned(ip: str) -> bool:
    info = FAILED_LOGINS.get(ip)
    if not info:
        return False
    now = time.time()
    banned_until = info.get("banned_until", 0)
    if banned_until > now:
        return True
    if banned_until and banned_until <= now:
        FAILED_LOGINS.pop(ip, None)
    return False


def register_failure(ip: str) -> None:
    now = time.time()
    rec = FAILED_LOGINS.setdefault(ip, {"fails": [], "banned_until": 0})
    if rec.get("banned_until", 0) > now:
        return
    rec["fails"] = [t for t in rec["fails"] if now - t < FAIL_WINDOW]
    rec["fails"].append(now)
    if len(rec["fails"]) >= FAIL_LIMIT:
        rec["banned_until"] = now + BAN_SECONDS
        rec["fails"] = []


def register_success(ip: str) -> None:
    FAILED_LOGINS.pop(ip, None)

@app.before_request
def require_login():
    public_endpoints = {"login", "static", "favicon"}
    if request.endpoint in public_endpoints:
        return
    uid = session.get("user_id")
    if not uid:
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))
    with get_db() as db:
        row = db.execute(
            "SELECT id, username, can_upload, must_change_password FROM users WHERE id=?",
            (uid,),
        ).fetchone()
    if not row:
        session.clear()
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))
    g.user = row
    session["username"] = row["username"]
    session["can_upload"] = bool(row["can_upload"])
    session["must_change_password"] = bool(row["must_change_password"])
    if session.get("must_change_password") and request.endpoint not in {"init_password", "logout"}:
        return redirect(url_for("init_password"))

@app.get("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = client_ip()
    if is_banned(ip):
        return (
            render_template(
                "message.html",
                message="Too many failed login attempts. Try again later.",
                back=url_for("login"),
            ),
            429,
        )

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        nxt = request.form.get("next")

        try:
            pow_data = session.get("pow", {})
            challenge = pow_data["challenge"]
            difficulty = pow_data["difficulty"]
            nonce = int(request.form.get("pow_nonce", ""))
        except (KeyError, TypeError, ValueError):
            challenge = None
        session.pop("pow", None)
        if not challenge:
            return (
                render_template(
                    "message.html",
                    message="Verification failed",
                    back=url_for("login"),
                ),
                400,
            )

        digest = hashlib.sha256(f"{challenge}{nonce}".encode()).hexdigest()
        if not digest.startswith("0" * difficulty):
            register_failure(ip)
            return (
                render_template(
                    "message.html",
                    message="Verification failed",
                    back=url_for("login"),
                ),
                400,
            )

        with get_db() as db:
            row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if row and check_password_hash(row["password_hash"], password):
            register_success(ip)
            session.clear()
            session.permanent = True
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["can_upload"] = bool(row["can_upload"])  # cache for template
            session["must_change_password"] = bool(row["must_change_password"])
            if session["must_change_password"]:
                return redirect(url_for("init_password"))
            if nxt and is_safe_url(nxt):
                return redirect(nxt)
            return redirect(url_for("dashboard"))
        register_failure(ip)
        return (
            render_template(
                "message.html",
                message="Invalid username or password",
                back=url_for("login"),
            ),
            401,
        )

    challenge = secrets.token_hex(8)
    difficulty = 3
    session["pow"] = {"challenge": challenge, "difficulty": difficulty}
    return render_template(
        "login.html",
        next=request.args.get("next", ""),
        challenge=challenge,
        difficulty=difficulty,
    )

@app.get("/dashboard")
def dashboard():
    files = []
    _reconcile_user_files(session.get("user_id"))
    with get_db() as db:
        rows = db.execute(
            "SELECT original_name, size, uploaded_at, is_public, token FROM files WHERE user_id=? ORDER BY uploaded_at DESC",
            (session.get("user_id"),),
        ).fetchall()
        for row in rows:
            files.append(
                {
                    "name": row["original_name"],
                    "size": row["size"],
                    "mtime": row["uploaded_at"],
                    "is_public": row["is_public"],
                    "token": row["token"],
                }
            )
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        can_upload=session.get("can_upload", False),
        user_id=session.get("user_id"),
        files=files,
    )


@app.get("/public")
def public_index():
    with get_db() as db:
        rows = db.execute(
            """
            SELECT files.original_name, files.size, files.uploaded_at, files.token, users.username
            FROM files
            JOIN users ON files.user_id = users.id
            WHERE files.is_public = 1
            ORDER BY users.username COLLATE NOCASE ASC, files.original_name COLLATE NOCASE ASC
            """
        ).fetchall()

    grouped = {}
    for row in rows:
        username = row["username"] or "Unknown"
        try:
            uploaded = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["uploaded_at"]))
        except (TypeError, ValueError, OSError):
            uploaded = "Unknown"
        entry = {
            "name": row["original_name"],
            "size": row["size"],
            "token": row["token"],
            "uploaded": uploaded,
        }
        grouped.setdefault(username, []).append(entry)

    def sort_key(value):
        return value.lower() if isinstance(value, str) else str(value).lower()

    groups = []
    for username in sorted(grouped, key=sort_key):
        files = grouped[username]
        files.sort(key=lambda f: sort_key(f["name"]))
        groups.append({"username": username, "files": files})

    return render_template("public.html", groups=groups)


@app.post("/upload/init")
def upload_init():
    is_xhr = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def err(msg, code):
        if is_xhr:
            return {"error": msg}, code
        return (
            render_template(
                "message.html", message=msg, back=url_for("dashboard")
            ),
            code,
        )

    if not session.get("user_id"):
        return err("Not authenticated", 401)

    if not session.get("can_upload"):
        return err("Uploads are disabled for your account", 403)

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    size = payload.get("size")
    chunk_size = payload.get("chunk_size")

    if not name:
        return err("Missing file name", 400)

    if size is None:
        return err("Missing file size", 400)

    try:
        size = int(size)
    except (TypeError, ValueError):
        return err("Invalid file size", 400)

    if size < 0:
        return err("Invalid file size", 400)

    if chunk_size is None:
        chunk_size = min(DEFAULT_CHUNK_SIZE, max(1, size or 1))

    try:
        chunk_size = int(chunk_size)
    except (TypeError, ValueError):
        return err("Invalid chunk size", 400)

    if chunk_size <= 0:
        return err("Invalid chunk size", 400)

    if chunk_size > app.config["MAX_CONTENT_LENGTH"]:
        chunk_size = app.config["MAX_CONTENT_LENGTH"]

    if size > app.config["MAX_CONTENT_LENGTH"]:
        return err("File exceeds maximum allowed size", 400)

    if not allowed_file(name):
        return err("File type not allowed", 400)

    safe_name = secure_filename(name)
    if not safe_name:
        return err("Invalid file name", 400)
    original_name = display_name(name, safe_name)

    user_path = user_dir()
    dest = user_path / safe_name
    temp_dest = user_path / f"{safe_name}.part"

    if dest.exists():
        if _register_existing_file(session.get("user_id"), safe_name, original_name):
            try:
                uploaded = dest.stat().st_size
            except OSError:
                uploaded = size
            return {"ok": True, "complete": True, "uploaded": uploaded}
        return err("File already exists", 400)

    if temp_dest.exists():
        return err("File already exists", 400)

    temp_dest.touch()

    if size == 0:
        ts = int(time.time())
        sha1 = hashlib.sha1()
        token = secrets.token_urlsafe(8)
        with get_db() as db:
            db.execute(
                "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token) VALUES(?,?,?,?,?,?,?)",
                (
                    session.get("user_id"),
                    safe_name,
                    original_name,
                    0,
                    ts,
                    sha1.hexdigest(),
                    token,
                ),
            )
        temp_dest.replace(dest)
        return {"ok": True, "complete": True}

    upload_token = secrets.token_urlsafe(16)
    with get_db() as db:
        db.execute(
            "INSERT INTO upload_sessions(token, user_id, stored_name, original_name, size, chunk_size, uploaded_bytes, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                upload_token,
                session.get("user_id"),
                safe_name,
                original_name,
                size,
                chunk_size,
                0,
                int(time.time()),
            ),
        )

    return {"ok": True, "token": upload_token, "chunk_size": chunk_size}


@app.post("/upload/chunk")
def upload_chunk():
    is_xhr = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def err(msg, code, extra=None):
        if is_xhr:
            payload = {"error": msg}
            if extra:
                payload.update(extra)
            return payload, code
        return (
            render_template(
                "message.html", message=msg, back=url_for("dashboard")
            ),
            code,
        )

    user_id = session.get("user_id")
    if not user_id:
        return err("Not authenticated", 401)

    if not session.get("can_upload"):
        return err("Uploads are disabled for your account", 403)

    token = request.form.get("token", "")
    offset_raw = request.form.get("offset", "")
    chunk = request.files.get("chunk")

    if not token or offset_raw == "" or chunk is None:
        return err("Missing upload data", 400)

    try:
        offset = int(offset_raw)
    except (TypeError, ValueError):
        return err("Invalid offset", 400)

    if offset < 0:
        return err("Invalid offset", 400)

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM upload_sessions WHERE token=?",
            (token,),
        ).fetchone()

    if not row or row["user_id"] != user_id:
        return err("Upload session not found", 404)

    if row["completed"]:
        final_path = user_dir() / row["stored_name"]
        if final_path.exists():
            return {
                "ok": True,
                "uploaded": row["uploaded_bytes"],
                "complete": True,
            }
        return err("Upload session not found", 404)

    expected = row["uploaded_bytes"]
    if offset != expected:
        if offset < expected:
            return {
                "ok": True,
                "uploaded": expected,
                "complete": bool(row["completed"]),
            }
        return err("Offset mismatch", 409, {"expected": expected, "complete": bool(row["completed"])})

    data = chunk.read()
    if data is None:
        data = b""

    if not data:
        return err("Empty chunk", 400)

    if len(data) > row["chunk_size"] and offset + len(data) < row["size"]:
        return err("Chunk too large", 400)

    if offset + len(data) > row["size"]:
        return err("Chunk exceeds declared size", 400)

    user_path = user_dir()
    temp_dest = user_path / f"{row['stored_name']}.part"
    if not temp_dest.exists():
        temp_dest.touch()

    with open(temp_dest, "r+b") as out:
        out.seek(offset)
        out.write(data)

    new_uploaded = offset + len(data)

    with get_db() as db:
        db.execute(
            "UPDATE upload_sessions SET uploaded_bytes=? WHERE token=?",
            (new_uploaded, token),
        )

    if new_uploaded < row["size"]:
        return {"ok": True, "uploaded": new_uploaded, "complete": False}

    final_path = user_path / row["stored_name"]
    if final_path.exists():
        final_path.unlink()

    temp_dest.replace(final_path)

    size = final_path.stat().st_size
    if size != row["size"]:
        # Something went wrong; keep the session for further retries
        temp_dest = final_path.with_name(f"{row['stored_name']}.part")
        final_path.replace(temp_dest)
        with get_db() as db:
            db.execute(
                "UPDATE upload_sessions SET uploaded_bytes=? WHERE token=?",
                (size, token),
            )
        return err("File size mismatch after upload", 500)

    file_token = secrets.token_urlsafe(8)
    ts = int(time.time())

    with get_db() as db:
        db.execute(
            "UPDATE upload_sessions SET uploaded_bytes=?, completed=1 WHERE token=?",
            (size, token),
        )
        cursor = db.execute(
            "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token) VALUES(?,?,?,?,?,?,?)",
            (
                user_id,
                row["stored_name"],
                row["original_name"],
                size,
                ts,
                SHA1_PLACEHOLDER,
                file_token,
            ),
        )

    file_id = cursor.lastrowid if cursor else None
    _schedule_sha1_update(user_id, row["stored_name"], file_id)

    return {"ok": True, "uploaded": size, "complete": True}


@app.post("/upload")
def upload():
    is_xhr = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def err(msg, code):
        if is_xhr:
            return {"error": msg}, code
        return (
            render_template(
                "message.html", message=msg, back=url_for("dashboard")
            ),
            code,
        )

    if not session.get("user_id"):
        return err("Not authenticated", 401)

    if not session.get("can_upload"):
        return err("Uploads are disabled for your account", 403)

    if "file" not in request.files:
        return err("No file field", 400)

    f = request.files["file"]
    if f.filename == "":
        return err("No file selected", 400)

    if not allowed_file(f.filename):
        return err("File type not allowed", 400)

    safe_name = secure_filename(f.filename)
    if not safe_name:
        return err("Invalid file name", 400)
    original_name = display_name(f.filename, safe_name)
    ts = int(time.time())
    stored = safe_name
    token = secrets.token_urlsafe(8)
    dest = user_dir() / stored
    if dest.exists():
        if _register_existing_file(session.get("user_id"), stored, original_name):
            if is_xhr:
                try:
                    uploaded = dest.stat().st_size
                except OSError:
                    uploaded = 0
                return {"ok": True, "uploaded": uploaded, "complete": True}
            return redirect(url_for("dashboard"))
        return err("File already exists", 400)

    sha1 = hashlib.sha1()
    with open(dest, "wb") as out:
        while True:
            chunk = f.stream.read(STREAM_COPY_CHUNK_SIZE)
            if not chunk:
                break
            sha1.update(chunk)
            out.write(chunk)
    size = dest.stat().st_size
    with get_db() as db:
        db.execute(
            "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token) VALUES(?,?,?,?,?,?,?)",
            (
                session.get("user_id"),
                stored,
                original_name,
                size,
                ts,
                sha1.hexdigest(),
                token,
            ),
        )

    if is_xhr:
        return {"ok": True}
    return redirect(url_for("dashboard"))


@app.post("/privacy/<token>")
def set_private(token):
    if not session.get("user_id"):
        abort(401)
    vals = request.form.getlist("private")
    private = vals[-1] == "1" if vals else False
    with get_db() as db:
        db.execute(
            "UPDATE files SET is_public=? WHERE user_id=? AND token=?",
            (0 if private else 1, session.get("user_id"), token),
        )
    return redirect(url_for("dashboard"))


@app.post("/delete/<token>")
def delete_file(token):
    if not session.get("user_id"):
        abort(401)
    with get_db() as db:
        row = db.execute(
            "SELECT id, user_id, stored_name FROM files WHERE token=?",
            (token,),
        ).fetchone()
        if not row or row["user_id"] != session.get("user_id"):
            abort(404)
        stored_name = row["stored_name"]
        owner_id = row["user_id"]
        db.execute("DELETE FROM file_accesses WHERE file_id=?", (row["id"],))
        db.execute(
            "DELETE FROM files WHERE id=? AND user_id=?",
            (row["id"], owner_id),
        )

    user_folder = (UPLOAD_ROOT / str(owner_id)).resolve()
    target = (user_folder / stored_name).resolve()
    if str(target).startswith(str(user_folder)) and target.is_file():
        try:
            target.unlink()
        except OSError:
            pass
    return redirect(url_for("dashboard"))
@app.get("/download/<token>")
def download(token):
    if not session.get("user_id"):
        abort(401)
    with get_db() as db:
        row = db.execute(
            "SELECT id, user_id, stored_name, is_public FROM files WHERE token=?",
            (token,),
        ).fetchone()
        if not row or (row["user_id"] != session.get("user_id") and not row["is_public"]):
            abort(404)
        if _should_increment_counter(db, row["id"], "download"):
            db.execute(
                "UPDATE files SET downloads = downloads + 1 WHERE id=?",
                (row["id"],),
            )
    d = (UPLOAD_ROOT / str(row["user_id"])).resolve()
    target = (d / row["stored_name"]).resolve()
    if not str(target).startswith(str(d)) or not target.exists() or not target.is_file():
        abort(404)
    return send_from_directory(d, target.name, as_attachment=True)


@app.get("/file/<token>")
def file_info(token):
    if not session.get("user_id"):
        abort(401)
    with get_db() as db:
        row = db.execute("SELECT * FROM files WHERE token=?", (token,)).fetchone()
        if not row or (row["user_id"] != session.get("user_id") and not row["is_public"]):
            abort(404)
        current_views = row["views"]
        if _should_increment_counter(db, row["id"], "view"):
            db.execute(
                "UPDATE files SET views = views + 1 WHERE id=?",
                (row["id"],),
            )
            current_views += 1
    d = (UPLOAD_ROOT / str(row["user_id"])).resolve()
    target = (d / row["stored_name"]).resolve()
    if not str(target).startswith(str(d)) or not target.exists() or not target.is_file():
        abort(404)
    info = dict(row)
    info["views"] = current_views
    info["uploaded_str"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(info["uploaded_at"]))
    info["sha1_pending"] = info.get("sha1") == SHA1_PLACEHOLDER
    if info["sha1_pending"]:
        _schedule_sha1_update(row["user_id"], row["stored_name"], row["id"])
    return render_template("file.html", file=info)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/init-password", methods=["GET", "POST"])
def init_password():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    if not session.get("must_change_password"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if not password:
            return (
                render_template(
                    "message.html",
                    message="Password required",
                    back=url_for("init_password"),
                ),
                400,
            )
        with get_db() as db:
            db.execute(
                "UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                (generate_password_hash(password), session.get("user_id")),
            )
        session["must_change_password"] = False
        return redirect(url_for("dashboard"))
    return render_template("init_password.html")

if __name__ == "__main__":
    init_db()
    cert = os.environ.get("SSL_CERT_FILE")
    key = os.environ.get("SSL_KEY_FILE")
    ssl_ctx = (cert, key) if cert and key else None
    app.run(host="0.0.0.0", port=8000, ssl_context=ssl_ctx)
