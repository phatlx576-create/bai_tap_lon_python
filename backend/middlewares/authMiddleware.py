import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

# Phải trùng với SECRET_KEY trong server.py
SECRET_KEY = os.environ.get("SECRET_KEY", "doi-khoa-bi-mat-nay-khi-nop-bai")
TOKEN_HOURS = 24


def create_token(user_id, username):
    """Tạo JWT có hạn 24 giờ."""
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    """Giải mã token. Trả về payload (dict) hoặc None nếu sai/hết hạn.
    Dùng được cho cả REST lẫn Socket.IO."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def token_required(f):
    """Decorator bảo vệ route. Client gửi header: Authorization: Bearer <token>.
    Sau khi qua, dùng g.user_id và g.username trong hàm xử lý."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Thiếu token đăng nhập"}), 401

        payload = decode_token(header[7:])
        if payload is None:
            return jsonify({"error": "Token không hợp lệ hoặc đã hết hạn"}), 401

        g.user_id = payload["user_id"]
        g.username = payload["username"]
        return f(*args, **kwargs)

    return wrapper