from flask import request
from flask_socketio import emit, join_room

from libs.db import get_db
from libs.socket import online_users, socketio
from middlewares.authMiddleware import decode_token

MAX_CIPHERTEXT_LEN = 20000   # giới hạn kích thước bản mã (base64)
HISTORY_LIMIT = 50

# sid của kết nối socket -> user_id
sid_to_user = {}


def _room(user_id):
    return f"user_{user_id}"


def _friend_ids(conn, user_id):
    rows = conn.execute(
        "SELECT CASE WHEN requester_id = ? THEN receiver_id ELSE requester_id END AS fid "
        "FROM friends WHERE (requester_id = ? OR receiver_id = ?) AND status = 'accepted'",
        (user_id, user_id, user_id),
    ).fetchall()
    return [r["fid"] for r in rows]


def _are_friends(conn, a, b):
    row = conn.execute(
        "SELECT 1 FROM friends WHERE status = 'accepted' AND "
        "((requester_id = ? AND receiver_id = ?) OR (requester_id = ? AND receiver_id = ?))",
        (a, b, b, a),
    ).fetchone()
    return row is not None


def _message_json(row):
    return {
        "id": row["id"],
        "sender_id": row["sender_id"],
        "receiver_id": row["receiver_id"],
        "ciphertext": row["ciphertext"],
        "iv": row["iv"],
        "created_at": row["created_at"],
    }


@socketio.on("connect")
def on_connect(auth):
    """Client kết nối bằng: io({ auth: { token: "<JWT>" } }).
    Token sai thì từ chối kết nối."""
    token = (auth or {}).get("token") if isinstance(auth, dict) else None
    payload = decode_token(token) if token else None
    if payload is None:
        return False  # từ chối

    user_id = payload["user_id"]
    sid_to_user[request.sid] = user_id
    first_connection = user_id not in online_users
    online_users.setdefault(user_id, set()).add(request.sid)
    join_room(_room(user_id))

    conn = get_db()
    try:
        friends = _friend_ids(conn, user_id)
    finally:
        conn.close()

    # Báo cho bạn bè biết mình online
    if first_connection:
        for fid in friends:
            emit("user_online", {"user_id": user_id}, room=_room(fid))

    # Gửi cho chính mình danh sách bạn đang online
    emit("online_list", [fid for fid in friends if fid in online_users])


@socketio.on("disconnect")
def on_disconnect(*args):
    user_id = sid_to_user.pop(request.sid, None)
    if user_id is None:
        return

    sids = online_users.get(user_id, set())
    sids.discard(request.sid)
    if sids:
        return  # vẫn còn tab khác đang mở
    online_users.pop(user_id, None)

    conn = get_db()
    try:
        friends = _friend_ids(conn, user_id)
    finally:
        conn.close()
    for fid in friends:
        emit("user_offline", {"user_id": user_id}, room=_room(fid))


@socketio.on("send_message")
def on_send_message(data):
    """Client gửi: {to: <user_id>, ciphertext: "...", iv: "..."}
    Server KHÔNG giải mã được, chỉ kiểm tra, lưu rồi chuyển tiếp bản mã."""
    sender_id = sid_to_user.get(request.sid)
    if sender_id is None:
        return {"ok": False, "error": "Chưa xác thực"}

    data = data if isinstance(data, dict) else {}
    to = data.get("to")
    ciphertext = data.get("ciphertext")
    iv = data.get("iv")

    if not isinstance(to, int) or to == sender_id:
        return {"ok": False, "error": "Người nhận không hợp lệ"}
    if not isinstance(ciphertext, str) or not isinstance(iv, str) or not ciphertext or not iv:
        return {"ok": False, "error": "Thiếu ciphertext hoặc iv"}
    if len(ciphertext) > MAX_CIPHERTEXT_LEN or len(iv) > 64:
        return {"ok": False, "error": "Tin nhắn quá dài"}

    conn = get_db()
    try:
        if not _are_friends(conn, sender_id, to):
            return {"ok": False, "error": "Hai bạn chưa là bạn bè"}

        cur = conn.execute(
            "INSERT INTO messages (sender_id, receiver_id, ciphertext, iv) VALUES (?, ?, ?, ?)",
            (sender_id, to, ciphertext, iv),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (cur.lastrowid,)).fetchone()
        message = _message_json(row)
    finally:
        conn.close()

    # Gửi cho người nhận (mọi tab) và các tab khác của người gửi
    emit("new_message", message, room=_room(to))
    emit("new_message", message, room=_room(sender_id), skip_sid=request.sid)

    return {"ok": True, "message": message}


@socketio.on("get_history")
def on_get_history(data):
    """Client gửi: {with: <user_id>, before_id: <tùy chọn, để tải thêm tin cũ hơn>}
    Trả về tối đa 50 tin (bản mã), sắp xếp từ cũ đến mới."""
    user_id = sid_to_user.get(request.sid)
    if user_id is None:
        return {"ok": False, "error": "Chưa xác thực"}

    data = data if isinstance(data, dict) else {}
    other = data.get("with")
    before_id = data.get("before_id")
    if not isinstance(other, int):
        return {"ok": False, "error": "Người dùng không hợp lệ"}

    conn = get_db()
    try:
        if not _are_friends(conn, user_id, other):
            return {"ok": False, "error": "Hai bạn chưa là bạn bè"}

        sql = (
            "SELECT * FROM messages WHERE "
            "((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))"
        )
        params = [user_id, other, other, user_id]
        if isinstance(before_id, int):
            sql += " AND id < ?"
            params.append(before_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(HISTORY_LIMIT)

        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    messages = [_message_json(r) for r in reversed(rows)]
    return {"ok": True, "messages": messages}