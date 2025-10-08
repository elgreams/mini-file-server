import sys
from pathlib import Path

sys.path.insert(0, str(Path("app").resolve()))
import user_admin


def test_user_admin_workflow(tmp_path):
    db = tmp_path / "app.db"
    user_admin.add_user("alice", "pw", True, False, db_path=str(db))
    user_admin.add_user("bob", "pw", False, True, db_path=str(db))
    users = user_admin.list_users(db_path=str(db))
    assert any(
        u["username"] == "alice" and u["can_upload"] == 1 and u["must_change_password"] == 0
        for u in users
    )
    assert any(
        u["username"] == "bob" and u["must_change_password"] == 1
        for u in users
    )

    user_admin.set_upload("alice", False, db_path=str(db))
    users = user_admin.list_users(db_path=str(db))
    alice = [u for u in users if u["username"] == "alice"][0]
    assert alice["can_upload"] == 0

    user_admin.delete_user("alice", db_path=str(db))
    user_admin.delete_user("bob", db_path=str(db))
    users = user_admin.list_users(db_path=str(db))
    assert users == []


def test_add_user_requires_password_change_by_default(tmp_path):
    db = tmp_path / "app.db"
    user_admin.add_user("carol", "pw", db_path=str(db))
    users = user_admin.list_users(db_path=str(db))
    assert users[0]["must_change_password"] == 1
