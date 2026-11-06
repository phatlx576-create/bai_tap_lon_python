from flask import g, jsonify, request

from libs.db import get_db


def _find_relation(conn, a, b):
    """Tìm bản ghi quan hệ giữa 2 user (theo cả hai chiều)."""
    return conn.execute(
        "SELECT * FROM friends WHERE "
        "(requester_id = ? AND receiver_id = ?) OR (requester_id = ? AND receiver_id = ?)",
        (a, b, b, a),
    ).fetchone()


def send_request():
    """POST /api/friends/request   Body: {"user_id": 5}
    Gửi lời mời kết bạn. Nếu người kia đã mời mình trước đó thì tự động chấp nhận."""
    data = request.get_json(silent=True) or {}
    target_id = data.get("user_id")

    if not isinstance(target_id, int):
        return jsonify({"error": "user_id không hợp lệ"}), 400
    if target_id == g.user_id:
        return jsonify({"error": "Không thể kết bạn với chính mình"}), 400

    conn = get_db()
    try:
        target = conn.execute("SELECT id FROM users WHERE id = ?", (target_id,)).fetchone()
        if target is None:
            return jsonify({"error": "Không tìm thấy người dùng"}), 404

        rel = _find_relation(conn, g.user_id, target_id)
        if rel is not None:
            if rel["status"] == "accepted":
                return jsonify({"error": "Hai bạn đã là bạn bè"}), 409
            if rel["requester_id"] == g.user_id:
                return jsonify({"error": "Bạn đã gửi lời mời rồi"}), 409
            # Người kia đã mời mình trước -> chấp nhận luôn
            conn.execute("UPDATE friends SET status = 'accepted' WHERE id = ?", (rel["id"],))
            conn.commit()
            return jsonify({"message": "Đã trở thành bạn bè", "status": "accepted"})

        conn.execute(
            "INSERT INTO friends (requester_id, receiver_id) VALUES (?, ?)",
            (g.user_id, target_id),
        )
        conn.commit()
        return jsonify({"message": "Đã gửi lời mời", "status": "pending"}), 201
    finally:
        conn.close()


def list_requests():
    """GET /api/friends/requests - các lời mời đang chờ mình trả lời."""
    conn = get_db()
    rows = conn.execute(
        "SELECT f.id AS request_id, u.id AS user_id, u.username, f.created_at "
        "FROM friends f JOIN users u ON u.id = f.requester_id "
        "WHERE f.receiver_id = ? AND f.status = 'pending' "
        "ORDER BY f.created_at DESC",
        (g.user_id,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


def accept_request(request_id):
    """POST /api/friends/<request_id>/accept - chỉ người nhận mới được chấp nhận."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM friends WHERE id = ? AND receiver_id = ? AND status = 'pending'",
            (request_id, g.user_id),
        ).fetchone()
        if row is None:
            return jsonify({"error": "Không tìm thấy lời mời"}), 404

        conn.execute("UPDATE friends SET status = 'accepted' WHERE id = ?", (request_id,))
        conn.commit()
        return jsonify({"message": "Đã chấp nhận lời mời"})
    finally:
        conn.close()


def decline_request(request_id):
    """POST /api/friends/<request_id>/decline - từ chối (xóa lời mời)."""
    conn = get_db()
    try:
        cur = conn.execute(
            "DELETE FROM friends WHERE id = ? AND receiver_id = ? AND status = 'pending'",
            (request_id, g.user_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"error": "Không tìm thấy lời mời"}), 404
        return jsonify({"message": "Đã từ chối lời mời"})
    finally:
        conn.close()


def list_friends():
    """GET /api/friends - danh sách bạn bè kèm khóa công khai (để tính khóa chung ECDH)."""
    conn = get_db()
    rows = conn.execute(
        "SELECT u.id, u.username, u.public_key "
        "FROM friends f JOIN users u "
        "  ON u.id = CASE WHEN f.requester_id = ? THEN f.receiver_id ELSE f.requester_id END "
        "WHERE (f.requester_id = ? OR f.receiver_id = ?) AND f.status = 'accepted' "
        "ORDER BY u.username",
        (g.user_id, g.user_id, g.user_id),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


def remove_friend(user_id):
    """DELETE /api/friends/<user_id> - hủy kết bạn."""
    conn = get_db()
    try:
        rel = _find_relation(conn, g.user_id, user_id)
        if rel is None or rel["status"] != "accepted":
            return jsonify({"error": "Hai bạn chưa là bạn bè"}), 404

        conn.execute("DELETE FROM friends WHERE id = ?", (rel["id"],))
        conn.commit()
        return jsonify({"message": "Đã hủy kết bạn"})
    finally:
        conn.close()
