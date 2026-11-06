from flask import request
from flask_socketio import emit, join_room

from libs.db import get_db
from libs.socket import online_users, socketio
from middlewares.authMiddleware import decode_token

MAX_TEXT_LEN = 20000        # độ dài tối đa bản mã của tin nhắn chữ (base64)
MAX_FILE_LEN = 6_000_000    # độ dài tối đa bản mã của tệp (base64, ~4 MB tệp gốc)
MAX_META_LEN = 2000         # thông tin tệp (đã mã hóa)
HISTORY_LIMIT = 50
KINDS = ("text", "file", "system")

# sid của kết nối socket -> user_id
sid_to_user = {}

# scope -> tên bảng (chỉ dùng giá trị cố định này để ghép vào SQL)
TABLES = {"dm": "messages", "group": "group_messages"}


# ============================ Hàm hỗ trợ ============================

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


def _group_member(conn, group_id, user_id):
    return conn.execute(
        "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone()


def _group_member_ids(conn, group_id):
    rows = conn.execute(
        "SELECT user_id FROM group_members WHERE group_id = ?", (group_id,)
    ).fetchall()
    return [r["user_id"] for r in rows]


def _shape(row):
    """Đổi 1 dòng DB thành JSON gửi cho client.
    Tệp luôn trả bản 'nhẹ' (không kèm bản mã), client tải riêng bằng get_blob."""
    deleted = row["deleted_at"] is not None
    keys = row.keys()
    out = {
        "id": row["id"],
        "sender_id": row["sender_id"],
        "kind": row["kind"],
        "ciphertext": row["ciphertext"],
        "iv": row["iv"],
        "meta": row["meta"],
        "created_at": row["created_at"],
        "deleted": deleted,
    }
    if "receiver_id" in keys:
        out["receiver_id"] = row["receiver_id"]
        out["read_at"] = row["read_at"]
    if "group_id" in keys:
        out["group_id"] = row["group_id"]

    if deleted:
        out["ciphertext"] = ""
        out["iv"] = ""
        out["meta"] = None
    elif row["kind"] == "file":
        out["size"] = len(row["ciphertext"])
        out["ciphertext"] = ""
        out["iv"] = ""
        out["lazy"] = True
    return out


def _parse_payload(data):
    """Kiểm tra dữ liệu tin nhắn client gửi. Trả về (lỗi, (kind, ciphertext, iv, meta))."""
    data = data if isinstance(data, dict) else {}
    kind = data.get("kind", "text")
    ciphertext = data.get("ciphertext")
    iv = data.get("iv")
    meta = data.get("meta")

    if kind not in KINDS:
        return "Loại tin nhắn không hợp lệ", None
    if not isinstance(ciphertext, str) or not isinstance(iv, str) or not ciphertext or not iv:
        return "Thiếu ciphertext hoặc iv", None
    limit = MAX_FILE_LEN if kind == "file" else MAX_TEXT_LEN
    if len(ciphertext) > limit or len(iv) > 64:
        return "Tin nhắn hoặc tệp quá lớn", None
    if kind == "file":
        if not isinstance(meta, str) or not meta or len(meta) > MAX_META_LEN:
            return "Thiếu thông tin tệp", None
    else:
        meta = None
    return None, (kind, ciphertext, iv, meta)


def _load_accessible(conn, scope, message_id, user_id):
    """Lấy tin nhắn nếu user có quyền xem, ngược lại trả None."""
    if scope not in TABLES or not isinstance(message_id, int):
        return None
    row = conn.execute(
        f"SELECT * FROM {TABLES[scope]} WHERE id = ?", (message_id,)
    ).fetchone()
    if row is None:
        return None
    if scope == "dm":
        return row if user_id in (row["sender_id"], row["receiver_id"]) else None
    member = _group_member(conn, row["group_id"], user_id)
    if member is None or row["id"] < member["joined_msg_id"]:
        return None
    return row


# ============================ Kết nối ============================

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


# ============================ Tin nhắn 1-1 ============================

@socketio.on("send_message")
def on_send_message(data):
    """Client gửi: {to, kind, ciphertext, iv, meta?}
    Server KHÔNG giải mã được, chỉ kiểm tra, lưu rồi chuyển tiếp bản mã."""
    sender_id = sid_to_user.get(request.sid)
    if sender_id is None:
        return {"ok": False, "error": "Chưa xác thực"}

    data = data if isinstance(data, dict) else {}
    to = data.get("to")
    if not isinstance(to, int) or to == sender_id:
        return {"ok": False, "error": "Người nhận không hợp lệ"}

    err, parsed = _parse_payload(data)
    if err:
        return {"ok": False, "error": err}
    kind, ciphertext, iv, meta = parsed

    conn = get_db()
    try:
        if not _are_friends(conn, sender_id, to):
            return {"ok": False, "error": "Hai bạn chưa là bạn bè"}

        cur = conn.execute(
            "INSERT INTO messages (sender_id, receiver_id, kind, ciphertext, iv, meta) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sender_id, to, kind, ciphertext, iv, meta),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (cur.lastrowid,)).fetchone()
        message = _shape(row)
    finally:
        conn.close()

    emit("new_message", message, room=_room(to))
    emit("new_message", message, room=_room(sender_id), skip_sid=request.sid)
    return {"ok": True, "message": message}


@socketio.on("get_history")
def on_get_history(data):
    """Client gửi: {with, before_id?}. Trả về tối đa 50 tin (bản mã), từ cũ đến mới.
    Không gồm tin mà người dùng đã 'Xóa với tôi'."""
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
            "((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)) "
            "AND id NOT IN (SELECT message_id FROM hidden_messages WHERE user_id = ? AND scope = 'dm')"
        )
        params = [user_id, other, other, user_id, user_id]
        if isinstance(before_id, int):
            sql += " AND id < ?"
            params.append(before_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(HISTORY_LIMIT)
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    return {"ok": True, "messages": [_shape(r) for r in reversed(rows)]}


@socketio.on("typing")
def on_typing(data):
    """Client gửi: {to: <user_id>} khi đang gõ. Server chỉ chuyển tiếp, không lưu gì."""
    user_id = sid_to_user.get(request.sid)
    to = data.get("to") if isinstance(data, dict) else None
    if user_id is None or not isinstance(to, int) or to == user_id:
        return

    conn = get_db()
    try:
        if not _are_friends(conn, user_id, to):
            return
    finally:
        conn.close()

    emit("typing", {"user_id": user_id}, room=_room(to))


@socketio.on("mark_read")
def on_mark_read(data):
    """Client gửi: {with: <user_id>} khi đã xem tin của người đó."""
    user_id = sid_to_user.get(request.sid)
    other = data.get("with") if isinstance(data, dict) else None
    if user_id is None or not isinstance(other, int):
        return {"ok": False}

    conn = get_db()
    try:
        cur = conn.execute(
            "UPDATE messages SET read_at = CURRENT_TIMESTAMP "
            "WHERE sender_id = ? AND receiver_id = ? AND read_at IS NULL",
            (other, user_id),
        )
        conn.commit()
        changed = cur.rowcount
    finally:
        conn.close()

    if changed:
        emit("messages_read", {"by": user_id}, room=_room(other))
    return {"ok": True}


# ============================ Tin nhắn nhóm ============================

@socketio.on("send_group_message")
def on_send_group_message(data):
    """Client gửi: {group_id, kind, ciphertext, iv, meta?} (mã hóa bằng khóa nhóm)."""
    sender_id = sid_to_user.get(request.sid)
    if sender_id is None:
        return {"ok": False, "error": "Chưa xác thực"}

    data = data if isinstance(data, dict) else {}
    group_id = data.get("group_id")
    if not isinstance(group_id, int):
        return {"ok": False, "error": "Nhóm không hợp lệ"}

    err, parsed = _parse_payload(data)
    if err:
        return {"ok": False, "error": err}
    kind, ciphertext, iv, meta = parsed

    conn = get_db()
    try:
        if _group_member(conn, group_id, sender_id) is None:
            return {"ok": False, "error": "Bạn không ở trong nhóm này"}

        cur = conn.execute(
            "INSERT INTO group_messages (group_id, sender_id, kind, ciphertext, iv, meta) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (group_id, sender_id, kind, ciphertext, iv, meta),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM group_messages WHERE id = ?", (cur.lastrowid,)).fetchone()
        message = _shape(row)
        member_ids = _group_member_ids(conn, group_id)
    finally:
        conn.close()

    for uid in member_ids:
        skip = request.sid if uid == sender_id else None
        emit("new_group_message", message, room=_room(uid), skip_sid=skip)
    return {"ok": True, "message": message}


@socketio.on("get_group_history")
def on_get_group_history(data):
    """Client gửi: {group_id, before_id?}. Thành viên mới chỉ thấy tin từ lúc được thêm."""
    user_id = sid_to_user.get(request.sid)
    if user_id is None:
        return {"ok": False, "error": "Chưa xác thực"}

    data = data if isinstance(data, dict) else {}
    group_id = data.get("group_id")
    before_id = data.get("before_id")
    if not isinstance(group_id, int):
        return {"ok": False, "error": "Nhóm không hợp lệ"}

    conn = get_db()
    try:
        member = _group_member(conn, group_id, user_id)
        if member is None:
            return {"ok": False, "error": "Bạn không ở trong nhóm này"}

        sql = (
            "SELECT * FROM group_messages WHERE group_id = ? AND id >= ? "
            "AND id NOT IN (SELECT message_id FROM hidden_messages WHERE user_id = ? AND scope = 'group')"
        )
        params = [group_id, member["joined_msg_id"], user_id]
        if isinstance(before_id, int):
            sql += " AND id < ?"
            params.append(before_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(HISTORY_LIMIT)
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    return {"ok": True, "messages": [_shape(r) for r in reversed(rows)]}


# ============================ Tệp, thu hồi, xóa ============================

@socketio.on("get_blob")
def on_get_blob(data):
    """Client gửi: {scope: "dm"|"group", id}. Trả về bản mã của tệp để client tự giải mã."""
    user_id = sid_to_user.get(request.sid)
    if user_id is None:
        return {"ok": False, "error": "Chưa xác thực"}
    data = data if isinstance(data, dict) else {}

    conn = get_db()
    try:
        row = _load_accessible(conn, data.get("scope"), data.get("id"), user_id)
    finally:
        conn.close()

    if row is None or row["kind"] != "file" or row["deleted_at"] is not None:
        return {"ok": False, "error": "Không tìm thấy tệp (có thể đã bị thu hồi)"}
    return {"ok": True, "ciphertext": row["ciphertext"], "iv": row["iv"]}


@socketio.on("recall_message")
def on_recall_message(data):
    """Client gửi: {scope, id}. Chỉ người gửi mới thu hồi được. Xóa hẳn bản mã khỏi DB."""
    user_id = sid_to_user.get(request.sid)
    if user_id is None:
        return {"ok": False, "error": "Chưa xác thực"}
    data = data if isinstance(data, dict) else {}
    scope = data.get("scope")

    conn = get_db()
    try:
        row = _load_accessible(conn, scope, data.get("id"), user_id)
        if row is None or row["sender_id"] != user_id:
            return {"ok": False, "error": "Bạn chỉ thu hồi được tin nhắn của chính mình"}
        if row["kind"] == "system":
            return {"ok": False, "error": "Không thể thu hồi thông báo hệ thống"}

        conn.execute(
            f"UPDATE {TABLES[scope]} SET ciphertext = '', iv = '', meta = NULL, "
            "deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL",
            (row["id"],),
        )
        conn.commit()

        if scope == "dm":
            targets = [(row["receiver_id"], user_id), (user_id, row["receiver_id"])]
        else:
            targets = [(uid, row["group_id"]) for uid in _group_member_ids(conn, row["group_id"])]
    finally:
        conn.close()

    # conv_id: id cuộc trò chuyện từ góc nhìn của người nhận sự kiện
    for uid, conv_id in targets:
        emit("message_recalled", {"scope": scope, "id": row["id"], "conv_id": conv_id}, room=_room(uid))
    return {"ok": True}


@socketio.on("delete_for_me")
def on_delete_for_me(data):
    """Client gửi: {scope, id}. Ẩn tin khỏi lịch sử của riêng người này."""
    user_id = sid_to_user.get(request.sid)
    if user_id is None:
        return {"ok": False, "error": "Chưa xác thực"}
    data = data if isinstance(data, dict) else {}

    conn = get_db()
    try:
        row = _load_accessible(conn, data.get("scope"), data.get("id"), user_id)
        if row is None:
            return {"ok": False, "error": "Không tìm thấy tin nhắn"}
        conn.execute(
            "INSERT OR IGNORE INTO hidden_messages (user_id, scope, message_id) VALUES (?, ?, ?)",
            (user_id, data["scope"], row["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}
