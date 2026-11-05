import json
import re
import sqlite3

import bcrypt
from flask import jsonify, request

from libs.db import get_db
from middlewares.authMiddleware import create_token

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def _user_json(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "public_key": row["public_key"],
    }


def register():
    """POST /api/auth/register
    Body: {"username": "...", "password": "...", "public_key": "<khóa công khai ECDH>"}
    Khóa bí mật được tạo và giữ ở trình duyệt, server chỉ nhận khóa công khai."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    public_key = data.get("public_key")

    if not USERNAME_RE.match(username):
        return jsonify({"error": "Tên đăng nhập 3-30 ký tự: chữ, số hoặc dấu _"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mật khẩu phải có ít nhất 6 ký tự"}), 400
    if len(password.encode("utf-8")) > 72:  # giới hạn của bcrypt
        return jsonify({"error": "Mật khẩu quá dài (tối đa 72 byte)"}), 400
    if not public_key:
        return jsonify({"error": "Thiếu khóa công khai"}), 400

    # Cho phép client gửi khóa dạng object (JWK) hoặc chuỗi
    if not isinstance(public_key, str):
        public_key = json.dumps(public_key)

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username, password_hash, public_key),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "Tên đăng nhập đã tồn tại"}), 409
    finally:
        conn.close()

    token = create_token(user_id, username)
    return jsonify({
        "token": token,
        "user": {"id": user_id, "username": username, "public_key": public_key},
    }), 201


def login():
    """POST /api/auth/login
    Body: {"username": "...", "password": "..."}"""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    ok = False
    if row is not None:
        try:
            ok = bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8"))
        except ValueError:
            ok = False

    if not ok:
        # Không tiết lộ là sai tên hay sai mật khẩu
        return jsonify({"error": "Sai tên đăng nhập hoặc mật khẩu"}), 401

    token = create_token(row["id"], row["username"])
    return jsonify({"token": token, "user": _user_json(row)})