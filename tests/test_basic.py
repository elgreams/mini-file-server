import io
import os, importlib.util, sys, hashlib, re, time
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

sys.path.insert(0, str(Path("app").resolve()))


def load_app():
    for mod in ["appmod", "config"]:
        if mod in sys.modules:
            del sys.modules[mod]
    spec = importlib.util.spec_from_file_location("appmod", "app/app.py")
    appmod = importlib.util.module_from_spec(spec)
    sys.modules["appmod"] = appmod
    spec.loader.exec_module(appmod)
    return appmod.app


def solve_pow(chal: str, diff: int) -> int:
    nonce = 0
    target = "0" * diff
    while True:
        digest = hashlib.sha256(f"{chal}{nonce}".encode()).hexdigest()
        if digest.startswith(target):
            return nonce
        nonce += 1


def login(c, username, password):
    c.get("/login")
    with c.session_transaction() as sess:
        pow = sess["pow"]
    nonce = solve_pow(pow["challenge"], pow["difficulty"])
    c.post(
        "/login",
        data={"username": username, "password": password, "pow_nonce": nonce},
    )


def test_redirect_login():
    app = load_app()
    with app.test_client() as c:
        r = c.get("/dashboard")
        assert r.status_code in (301, 302)
        assert "/login" in r.location


def test_login_page_includes_pow_field():
    app = load_app()
    with app.test_client() as c:
        r = c.get("/login")
        text = r.get_data(as_text=True)
        assert "pow_nonce" in text


def test_pow_nonce_uses_decimal_representation():
    app = load_app()
    with app.test_client() as c:
        r = c.get("/login")
        text = r.get_data(as_text=True)
        # The client-side script should hash using the decimal string of the
        # nonce. A hexadecimal conversion such as `chal + nonce.toString(16)`
        # would break the server verification step.
        assert "chal + nonce.toString(16)" not in text


def test_login_button_disabled_initially():
    app = load_app()
    with app.test_client() as c:
        r = c.get("/login")
        text = r.get_data(as_text=True)
        assert re.search(r'<button[^>]*id="loginBtn"[^>]*disabled', text)


def test_login_fields_support_autocomplete_and_remember_username():
    app = load_app()
    with app.test_client() as c:
        r = c.get("/login")
        text = r.get_data(as_text=True)
        assert 'autocomplete="username"' in text
        assert 'autocomplete="current-password"' in text
        assert 'id="remember_username"' in text


def test_login_requires_pow():
    app = load_app()
    with app.test_client() as c:
        c.get("/login")
        r = c.post("/login", data={"username": "u", "password": "p"})
        assert r.status_code == 400


def test_filesize_filter_handles_large_values():
    load_app()
    appmod = sys.modules["appmod"]
    assert appmod.filesize_filter(252_122_712) == "240 MB"
    assert appmod.filesize_filter(25_212_271) == "24 MB"
    assert appmod.filesize_filter(1_536) == "1.5 KB"


def test_public_page_lists_public_files_by_user(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.UPLOAD_ROOT = tmp_path / "uploads"
    appmod.UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("alice", generate_password_hash("pw")),
        )
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("bob", generate_password_hash("pw")),
        )
        alice_id = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("alice",),
        ).fetchone()[0]
        bob_id = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("bob",),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token) VALUES(?,?,?,?,?,?,?)",
            (
                alice_id,
                "alice-report.txt",
                "alice-report.txt",
                10,
                1,
                "sha1alice",
                "tok-alice",
            ),
        )
        conn.execute(
            "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token) VALUES(?,?,?,?,?,?,?)",
            (
                bob_id,
                "bob-notes.txt",
                "bob-notes.txt",
                20,
                2,
                "sha1bob",
                "tok-bob",
            ),
        )
        conn.execute(
            "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token, is_public) VALUES(?,?,?,?,?,?,?,?)",
            (
                alice_id,
                "secret.txt",
                "secret.txt",
                30,
                3,
                "sha1secret",
                "tok-secret",
                0,
            ),
        )

    with app.test_client() as c:
        response = c.get("/public")
        assert response.status_code in (301, 302)
        location = response.headers.get("Location", "")
        parsed = urlparse(location)
        assert parsed.path.endswith("/login")
        params = parse_qs(parsed.query)
        assert params.get("next") == ["/public"]

        login(c, "alice", "pw")
        response = c.get("/public")
        assert response.status_code == 200
        text = response.get_data(as_text=True)
        assert "alice-report.txt" in text
        assert "bob-notes.txt" in text
        assert "secret.txt" not in text
        assert "<summary>alice" in text
        assert "<summary>bob" in text
        assert text.index("<summary>alice") < text.index("<summary>bob")


def test_favicon_served():
    icon = Path("app/static/favicon.ico")
    icon.write_bytes(b"0")
    app = load_app()
    try:
        with app.test_client() as c:
            r = c.get("/favicon.ico")
            assert r.status_code == 200
            assert r.mimetype == "image/vnd.microsoft.icon"
    finally:
        icon.unlink()


def test_password_change_required(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload, must_change_password) VALUES(?,?,?,1)",
            ("alice", generate_password_hash("pw"), 1),
        )
    with app.test_client() as c:
        c.get("/login")
        with c.session_transaction() as sess:
            pow = sess["pow"]
        nonce = solve_pow(pow["challenge"], pow["difficulty"])
        r = c.post("/login", data={"username": "alice", "password": "pw", "pow_nonce": nonce})
        assert r.status_code in (301, 302)
        assert r.headers["Location"].endswith("/init-password")

        r = c.get("/dashboard")
        assert r.status_code in (301, 302)
        assert r.headers["Location"].endswith("/init-password")

        r = c.post("/init-password", data={"password": "new"})
        assert r.status_code in (301, 302)
        assert r.headers["Location"].endswith("/dashboard")

        r = c.get("/dashboard")
        assert r.status_code == 200


def test_upload_returns_json_error(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("bob", generate_password_hash("pw")),
        )
    with app.test_client() as c:
        c.get("/login")
        with c.session_transaction() as sess:
            pow = sess["pow"]
        nonce = solve_pow(pow["challenge"], pow["difficulty"])
        c.post("/login", data={"username": "bob", "password": "pw", "pow_nonce": nonce})
        r = c.post("/upload", headers={"X-Requested-With": "XMLHttpRequest"}, data={})
        assert r.status_code == 400
        assert r.is_json
        assert "error" in r.get_json()


def test_chunked_upload_resume(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.UPLOAD_ROOT = tmp_path / "uploads"
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("alice", generate_password_hash("pw")),
        )
        uid = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("alice",),
        ).fetchone()[0]

    with app.test_client() as c:
        login(c, "alice", "pw")
        content = (b"hello world" * 1024) + b"!"
        chunk_size = 1024
        init_resp = c.post(
            "/upload/init",
            json={"name": "demo.txt", "size": len(content), "chunk_size": chunk_size},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert init_resp.status_code == 200
        init_data = init_resp.get_json()
        assert init_data["ok"]
        token = init_data["token"]

        first = content[:chunk_size]
        resp = c.post(
            "/upload/chunk",
            data={
                "token": token,
                "offset": "0",
                "chunk": (io.BytesIO(first), "chunk.bin"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"]
        assert data["uploaded"] == chunk_size
        assert not data["complete"]

        resp = c.post(
            "/upload/chunk",
            data={
                "token": token,
                "offset": "0",
                "chunk": (io.BytesIO(first), "chunk.bin"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"]
        assert data["uploaded"] == chunk_size
        assert not data["complete"]

        remaining = content[chunk_size:]
        resp = c.post(
            "/upload/chunk",
            data={
                "token": token,
                "offset": str(chunk_size),
                "chunk": (io.BytesIO(remaining), "chunk.bin"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"]
        assert data["complete"]

        resp = c.post(
            "/upload/chunk",
            data={
                "token": token,
                "offset": str(chunk_size),
                "chunk": (io.BytesIO(remaining), "chunk.bin"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"]
        assert data["complete"]

    stored = appmod.UPLOAD_ROOT / str(uid) / "demo.txt"
    assert stored.exists()
    assert stored.read_bytes() == content

    with appmod.get_db() as conn:
        file_row = conn.execute(
            "SELECT original_name, size FROM files WHERE user_id=?",
            (uid,),
        ).fetchone()
        assert file_row["original_name"] == "demo.txt"
        assert file_row["size"] == len(content)

    expected_sha1 = hashlib.sha1(content).hexdigest()
    digest = None
    deadline = time.time() + 5
    while time.time() < deadline:
        with appmod.get_db() as conn:
            digest = conn.execute(
                "SELECT sha1 FROM files WHERE user_id=?",
                (uid,),
            ).fetchone()["sha1"]
        if digest != appmod.SHA1_PLACEHOLDER:
            break
        time.sleep(0.05)

    assert digest == expected_sha1


def test_dashboard_shows_original_filename(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.UPLOAD_ROOT = tmp_path / "uploads"
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("alice", generate_password_hash("pw")),
        )
        uid = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("alice",),
        ).fetchone()[0]

    raw_name = "C\\\\fakepath\\\\My Report (Final).txt"
    expected_stored = secure_filename(raw_name)
    expected_original = "My Report (Final).txt"
    content = b"hello"

    with app.test_client() as c:
        login(c, "alice", "pw")
        init_resp = c.post(
            "/upload/init",
            json={"name": raw_name, "size": len(content), "chunk_size": len(content)},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        token = init_resp.get_json()["token"]
        c.post(
            "/upload/chunk",
            data={
                "token": token,
                "offset": "0",
                "chunk": (io.BytesIO(content), "chunk.bin"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="multipart/form-data",
        )

        with appmod.get_db() as conn:
            row = conn.execute(
                "SELECT stored_name, original_name FROM files WHERE user_id=?",
                (uid,),
            ).fetchone()
            assert row["stored_name"] == expected_stored
            assert row["original_name"] == expected_original

        resp = c.get("/dashboard")
        html = resp.get_data(as_text=True)
        assert expected_original in html
        assert expected_stored not in html


def test_dashboard_registers_orphaned_files(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.UPLOAD_ROOT = tmp_path / "uploads"
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("alice", generate_password_hash("pw")),
        )
        uid = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("alice",),
        ).fetchone()[0]

    content = b"ghost data"
    user_dir = appmod.UPLOAD_ROOT / str(uid)
    user_dir.mkdir(parents=True, exist_ok=True)
    orphan = user_dir / "ghost.txt"
    orphan.write_bytes(content)

    with app.test_client() as c:
        login(c, "alice", "pw")
        resp = c.get("/dashboard")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "ghost.txt" in body

    with appmod.get_db() as conn:
        row = conn.execute(
            "SELECT original_name, size FROM files WHERE user_id=? AND stored_name=?",
            (uid, "ghost.txt"),
        ).fetchone()
        assert row is not None
        assert row["original_name"] == "ghost.txt"
        assert row["size"] == len(content)


def test_upload_init_recovers_existing_file(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.UPLOAD_ROOT = tmp_path / "uploads"
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("alice", generate_password_hash("pw")),
        )
        uid = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("alice",),
        ).fetchone()[0]

    content = b"hello"
    user_dir = appmod.UPLOAD_ROOT / str(uid)
    user_dir.mkdir(parents=True, exist_ok=True)
    existing = user_dir / "demo.txt"
    existing.write_bytes(content)

    with app.test_client() as c:
        login(c, "alice", "pw")
        resp = c.post(
            "/upload/init",
            json={"name": "demo.txt", "size": len(content), "chunk_size": len(content)},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"]
        assert data["complete"]
        assert data["uploaded"] == len(content)

    with appmod.get_db() as conn:
        row = conn.execute(
            "SELECT original_name, size FROM files WHERE user_id=? AND stored_name=?",
            (uid, "demo.txt"),
        ).fetchone()
        assert row is not None
        assert row["original_name"] == "demo.txt"
        assert row["size"] == len(content)

def test_failures_trigger_ban():
    app = load_app()
    appmod = sys.modules["appmod"]
    with app.test_client() as c:
        for _ in range(appmod.FAIL_LIMIT):
            c.get("/login")
            with c.session_transaction() as sess:
                pow = sess["pow"]
            nonce = solve_pow(pow["challenge"], pow["difficulty"])
            c.post("/login", data={"username": "u", "password": "bad", "pow_nonce": nonce})
        r = c.post("/login", data={"username": "u", "password": "bad"})
        assert r.status_code == 429


def test_allowed_file_all_extensions(monkeypatch):
    monkeypatch.delenv("APP_ALLOWED_EXTS", raising=False)
    app = load_app()
    appmod = sys.modules["appmod"]
    assert appmod.allowed_file("file.weird")
    assert not appmod.allowed_file("file")


def test_default_max_content_length(monkeypatch):
    monkeypatch.delenv("APP_MAX_CONTENT_MB", raising=False)
    app = load_app()
    assert app.config["MAX_CONTENT_LENGTH"] == 10 * 1024 * 1024 * 1024


def test_public_private_file_access(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.UPLOAD_ROOT = tmp_path / "uploads"
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("alice", generate_password_hash("pw")),
        )
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("bob", generate_password_hash("pw")),
        )
        uid_alice = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("alice",),
        ).fetchone()[0]
        user_dir = appmod.UPLOAD_ROOT / str(uid_alice)
        user_dir.mkdir(parents=True, exist_ok=True)
        content = b"hello"
        (user_dir / "test.txt").write_bytes(content)
        token = "tok123"
        conn.execute(
            "INSERT INTO files(user_id, stored_name, original_name, size, uploaded_at, sha1, token) VALUES(?,?,?,?,?,?,?)",
            (
                uid_alice,
                "test.txt",
                "test.txt",
                len(content),
                0,
                hashlib.sha1(content).hexdigest(),
                token,
            ),
        )

    with app.test_client() as c:
        login(c, "bob", "pw")
        r = c.get(f"/download/{token}")
        assert r.status_code == 200
        c.get("/logout")

        login(c, "alice", "pw")
        c.post(f"/privacy/{token}", data={"private": "1"})
        c.get("/logout")

        login(c, "bob", "pw")
        r = c.get(f"/download/{token}")
        assert r.status_code == 404


def test_session_invalid_after_user_deletion(tmp_path):
    app = load_app()
    appmod = sys.modules["appmod"]
    db = tmp_path / "app.db"
    appmod.DB_PATH = str(db)
    appmod.init_db()
    with appmod.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload) VALUES(?,?,1)",
            ("alice", generate_password_hash("pw")),
        )
    with app.test_client() as c:
        login(c, "alice", "pw")
        with appmod.get_db() as conn:
            conn.execute("DELETE FROM users WHERE username=?", ("alice",))
        r = c.get("/dashboard")
        assert r.status_code in (301, 302)
        assert "/login" in r.headers["Location"]
