from flask import g, jsonify, request

from libs.db import get_db


def get_me():
    """GET /api/users/me - thông tin người dùng đang đăng nhập."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, public_key FROM users WHERE id = ?", (g.user_id,)
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "Không tìm thấy người dùng"}), 404
    return jsonify(dict(row))


def search_users():
    """GET /api/users/search?q=abc - tìm user theo tên (không gồm chính mình).
    Kèm trạng thái quan hệ: none | friends | pending_sent | pending_received."""
    q = (request.args.get("q") or "").strip()
    if len(q) < 1:
        return jsonify([])

    # Escape ký tự đặc biệt của LIKE để người dùng gõ % hoặc _ không bị lệch kết quả
    safe = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    conn = get_db()
    users = conn.execute(
        "SELECT id, username FROM users "
        "WHERE username LIKE ? ESCAPE '\\' AND id != ? "
        "ORDER BY username LIMIT 20",
        (f"%{safe}%", g.user_id),
    ).fetchall()

    relations = conn.execute(
        "SELECT requester_id, receiver_id, status FROM friends "
        "WHERE requester_id = ? OR receiver_id = ?",
        (g.user_id, g.user_id),
    ).fetchall()
    conn.close()

    # Dựng bảng tra: id người kia -> trạng thái
    status_of = {}
    for r in relations:
        if r["requester_id"] == g.user_id:
            other = r["receiver_id"]
            status_of[other] = "friends" if r["status"] == "accepted" else "pending_sent"
        else:
            other = r["requester_id"]
            status_of[other] = "friends" if r["status"] == "accepted" else "pending_received"

    return jsonify([
        {"id": u["id"], "username": u["username"], "relation": status_of.get(u["id"], "none")}
        for u in users
    ])


def get_public_key(user_id):
    """GET /api/users/<id>/public-key - lấy khóa công khai để tính khóa chung ECDH.
    Khóa công khai vốn không bí mật nên mọi user đã đăng nhập đều lấy được."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, public_key FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "Không tìm thấy người dùng"}), 404
    return jsonify(dict(row))