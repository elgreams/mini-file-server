import argparse, getpass, os, sqlite3
from pathlib import Path
from typing import Union
from werkzeug.security import generate_password_hash

# Allow the database location to be overridden via an environment variable.
# To ensure the CLI tools and the running server point at the same database by
# default, place it in a hidden directory relative to the repository root. This
# avoids accidental creation of separate databases when the scripts are run
# outside the container hosting the server.
DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent / ".vibe-data"
DB_PATH = Path(os.environ.get("VIBE_DB_PATH", DEFAULT_DB_DIR / "app.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def get_conn(db_path: Union[Path, str] = DB_PATH):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute(
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
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "must_change_password" not in cols:
        conn.execute(
            "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
        )
    return conn

def add_user(
    username: str,
    password: str,
    can_upload: bool = False,
    must_change_password: bool = True,
    db_path: Union[Path, str] = DB_PATH,
):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, can_upload, must_change_password) VALUES(?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                1 if can_upload else 0,
                1 if must_change_password else 0,
            ),
        )

def list_users(db_path: Union[Path, str] = DB_PATH):
    with get_conn(db_path) as conn:
        return conn.execute(
            "SELECT id, username, can_upload, must_change_password FROM users ORDER BY id"
        ).fetchall()

def set_upload(username: str, value: bool, db_path: Union[Path, str] = DB_PATH):
    with get_conn(db_path) as conn:
        conn.execute("UPDATE users SET can_upload=? WHERE username=?", (1 if value else 0, username))

def set_must_change_password(
    username: str, value: bool, db_path: Union[Path, str] = DB_PATH
):
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE users SET must_change_password=? WHERE username=?",
            (1 if value else 0, username),
        )

def delete_user(username: str, db_path: Union[Path, str] = DB_PATH):
    with get_conn(db_path) as conn:
        conn.execute("DELETE FROM users WHERE username=?", (username,))

def set_password(username: str, password: str, db_path: Union[Path, str] = DB_PATH):
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?",
            (generate_password_hash(password), username),
        )

def main():
    parser = argparse.ArgumentParser(description="Manage users for the file server.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Create a new user")
    p_add.add_argument("username")
    p_add.add_argument("--can-upload", action="store_true")
    # By default newly created users must change their password on first login
    # unless this flag is provided.
    p_add.add_argument(
        "--no-must-change-password",
        action="store_false",
        dest="must_change_password",
        help="Allow the user to keep the initial password",
    )

    sub.add_parser("list", help="List users")

    p_set = sub.add_parser("set-upload", help="Enable or disable uploads for a user")
    p_set.add_argument("username")
    p_set.add_argument("value", choices=["y", "n", "yes", "no", "1", "0", "true", "false"])

    p_must = sub.add_parser(
        "set-must-change",
        help="Require or clear a password change on the next login",
    )
    p_must.add_argument("username")
    p_must.add_argument("value", choices=["y", "n", "yes", "no", "1", "0", "true", "false"])

    p_del = sub.add_parser("delete", help="Delete a user")
    p_del.add_argument("username")

    p_pass = sub.add_parser("passwd", help="Change a user's password")
    p_pass.add_argument("username")

    args = parser.parse_args()

    if args.cmd == "add":
        password = getpass.getpass("Password: ")
        if not password:
            print("Password required"); raise SystemExit(1)
        add_user(args.username, password, args.can_upload, args.must_change_password)
        print(f"User '{args.username}' created.")
    elif args.cmd == "list":
        for row in list_users():
            flag = "y" if row["can_upload"] else "n"
            pw = "y" if row["must_change_password"] else "n"
            print(
                f"{row['id']}\t{row['username']}\tcan_upload={flag}\tmust_change_password={pw}"
            )
    elif args.cmd == "set-upload":
        value = args.value.lower() in ("y", "yes", "1", "true")
        set_upload(args.username, value)
    elif args.cmd == "set-must-change":
        value = args.value.lower() in ("y", "yes", "1", "true")
        set_must_change_password(args.username, value)
    elif args.cmd == "delete":
        delete_user(args.username)
    elif args.cmd == "passwd":
        password = getpass.getpass("New password: ")
        if not password:
            print("Password required"); raise SystemExit(1)
        set_password(args.username, password)

if __name__ == "__main__":
    main()
