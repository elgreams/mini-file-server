import sqlite3, getpass, os
from pathlib import Path
from werkzeug.security import generate_password_hash

# Store the SQLite database alongside the application by default so that
# administrative scripts run on the host and the server process running inside
# a container operate on the same file. A custom location may still be provided
# via the VIBE_DB_PATH environment variable.
DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent / ".vibe-data"
DB_PATH = Path(os.environ.get("VIBE_DB_PATH", DEFAULT_DB_DIR / "app.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
conn = sqlite3.connect(str(DB_PATH))
conn.execute(
    """CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  can_upload INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 0
)"""
)
cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
if "must_change_password" not in cols:
    conn.execute(
        "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
    )

u = input("New username: ").strip()
p = getpass.getpass("Password: ")
flag = input("Can upload? [y/N]: ").strip().lower().startswith("y")
# Require a password change on first login by default. Users can opt out
# by answering with "n".
must = not input("Require password change on first login? [Y/n]: ").strip().lower().startswith("n")
if not u or not p:
    print("Username and password required")
    raise SystemExit(1)
try:
    conn.execute(
        "INSERT INTO users(username, password_hash, can_upload, must_change_password) VALUES(?,?,?,?)",
        (u, generate_password_hash(p), 1 if flag else 0, 1 if must else 0),
    )
    conn.commit()
    print(f"User '{u}' created (can_upload={flag}, must_change_password={must}).")
except sqlite3.IntegrityError:
    print("Username already exists.")
finally:
    conn.close()
