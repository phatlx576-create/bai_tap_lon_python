from flask import g, jsonify, request

from libs.db import get_db
from libs.socket import socketio

MAX_MEMBERS = 50


def _notify(user_ids, group_id):
    """Báo cho các user biết danh sách nhóm của họ đã thay đổi (client sẽ tải lại)."""
    for uid in set(user_ids):
        socketio.emit("groups_changed", {"group_id": group_id}, room=f"user_{uid}")


def _friend_ids(conn, user_id):
    rows = conn.execute(
        "SELECT CASE WHEN requester_id = ? THEN receiver_id ELSE requester_id END AS fid "
        "FROM friends WHERE (requester_id = ? OR receiver_id = ?) AND status = 'accepted'",
        (user_id, user_id, user_id),
    ).fetchall()
    return {r["fid"] for r in rows}


def _member_ids(conn, group_id):
    rows = conn.execute("SELECT user_id FROM group_members WHERE group_id = ?", (group_id,)).fetchall()
    return [r["user_id"] for r in rows]


def _group_json(conn, group_id, user_id):
    """Thông tin nhóm + khóa nhóm đã gói dành riêng cho user_id."""
    grp = conn.execute(
        "SELECT id, name, owner_id, created_at FROM groups WHERE id = ?", (group_id,)
    ).fetchone()
    if grp is None:
        return None

    members = conn.execute(
        "SELECT u.id, u.username, gm.role FROM group_members gm "
        "JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ? "
        "ORDER BY gm.role DESC, u.username",
        (group_id,),
    ).fetchall()

    key = conn.execute(
        "SELECT gm.key_ct, gm.key_iv, gm.wrapper_id, u.public_key AS wrapper_public_key "
        "FROM group_members gm JOIN users u ON u.id = gm.wrapper_id "
        "WHERE gm.group_id = ? AND gm.user_id = ?",
        (group_id, user_id),
    ).fetchone()
    if key is None:
        return None

    return {
        "id": grp["id"],
        "name": grp["name"],
        "owner_id": grp["owner_id"],
        "created_at": grp["created_at"],
        "members": [dict(m) for m in members],
        "my_key": {
            "ciphertext": key["key_ct"],
            "iv": key["key_iv"],
            "wrapper_id": key["wrapper_id"],
            "wrapper_public_key": key["wrapper_public_key"],
        },
    }


def _valid_wrap(entry):
    """Kiểm tra 1 khóa nhóm đã gói: {user_id, ciphertext, iv}."""
    if not isinstance(entry, dict):
        return False
    uid, ct, iv = entry.get("user_id"), entry.get("ciphertext"), entry.get("iv")
    return (
        isinstance(uid, int) and not isinstance(uid, bool)
        and isinstance(ct, str) and 0 < len(ct) <= 500
        and isinstance(iv, str) and 0 < len(iv) <= 64
    )


def list_groups():
    """GET /api/groups - các nhóm mình đang tham gia."""
    conn = get_db()
    try:
        ids = [
            r["group_id"]
            for r in conn.execute(
                "SELECT group_id FROM group_members WHERE user_id = ? ORDER BY group_id DESC",
                (g.user_id,),
            ).fetchall()
        ]
        return jsonify([j for j in (_group_json(conn, gid, g.user_id) for gid in ids) if j])
    finally:
        conn.close()


def create_group():
    """POST /api/groups
    Body: {"name": "...", "members": [{"user_id", "ciphertext", "iv"}, ...]}
    Trong đó ciphertext/iv là khóa nhóm (AES) đã được người tạo mã hóa riêng cho từng
    thành viên (gồm cả chính mình). Server không bao giờ thấy khóa nhóm."""
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    members = data.get("members")

    if not name or len(name) > 50:
        return jsonify({"error": "Tên nhóm phải có 1-50 ký tự"}), 400
    if not isinstance(members, list) or not (2 <= len(members) <= MAX_MEMBERS):
        return jsonify({"error": f"Nhóm cần từ 2 đến {MAX_MEMBERS} thành viên"}), 400
    if not all(_valid_wrap(m) for m in members):
        return jsonify({"error": "Dữ liệu thành viên không hợp lệ"}), 400

    entries = {m["user_id"]: (m["ciphertext"], m["iv"]) for m in members}
    if len(entries) != len(members) or g.user_id not in entries:
        return jsonify({"error": "Danh sách thành viên không hợp lệ"}), 400

    conn = get_db()
    try:
        friends = _friend_ids(conn, g.user_id)
        if any(uid != g.user_id and uid not in friends for uid in entries):
            return jsonify({"error": "Chỉ thêm được bạn bè vào nhóm"}), 400

        cur = conn.execute("INSERT INTO groups (name, owner_id) VALUES (?, ?)", (name, g.user_id))
        gid = cur.lastrowid
        for uid, (ct, iv) in entries.items():
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, role, wrapper_id, key_ct, key_iv) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (gid, uid, "owner" if uid == g.user_id else "member", g.user_id, ct, iv),
            )
        conn.commit()
        out = _group_json(conn, gid, g.user_id)
    finally:
        conn.close()

    _notify(entries.keys(), gid)
    return jsonify(out), 201


def add_member(group_id):
    """POST /api/groups/<id>/members   Body: {"user_id", "ciphertext", "iv"}  (chỉ chủ nhóm)."""
    data = request.get_json(silent=True) or {}
    if not _valid_wrap(data):
        return jsonify({"error": "Dữ liệu không hợp lệ"}), 400
    new_id = data["user_id"]

    conn = get_db()
    try:
        grp = conn.execute("SELECT owner_id FROM groups WHERE id = ?", (group_id,)).fetchone()
        if grp is None:
            return jsonify({"error": "Không tìm thấy nhóm"}), 404
        if grp["owner_id"] != g.user_id:
            return jsonify({"error": "Chỉ chủ nhóm mới thêm được thành viên"}), 403

        members = _member_ids(conn, group_id)
        if new_id in members:
            return jsonify({"error": "Người này đã ở trong nhóm"}), 409
        if len(members) >= MAX_MEMBERS:
            return jsonify({"error": "Nhóm đã đủ thành viên"}), 400
        if new_id not in _friend_ids(conn, g.user_id):
            return jsonify({"error": "Chỉ thêm được bạn bè vào nhóm"}), 400

        # Thành viên mới chỉ thấy tin nhắn từ thời điểm được thêm
        first_id = conn.execute(
            "SELECT COALESCE(MAX(id), 0) + 1 AS n FROM group_messages WHERE group_id = ?",
            (group_id,),
        ).fetchone()["n"]
        conn.execute(
            "INSERT INTO group_members (group_id, user_id, role, wrapper_id, key_ct, key_iv, joined_msg_id) "
            "VALUES (?, ?, 'member', ?, ?, ?, ?)",
            (group_id, new_id, g.user_id, data["ciphertext"], data["iv"], first_id),
        )
        conn.commit()
        out = _group_json(conn, group_id, g.user_id)
        all_members = _member_ids(conn, group_id)
    finally:
        conn.close()

    _notify(all_members, group_id)
    return jsonify(out)


def remove_member(group_id, user_id):
    """DELETE /api/groups/<id>/members/<user_id>
    Chủ nhóm xóa thành viên, hoặc thành viên tự rời nhóm."""
    conn = get_db()
    try:
        grp = conn.execute("SELECT owner_id FROM groups WHERE id = ?", (group_id,)).fetchone()
        if grp is None:
            return jsonify({"error": "Không tìm thấy nhóm"}), 404
        if g.user_id != grp["owner_id"] and g.user_id != user_id:
            return jsonify({"error": "Bạn không có quyền xóa thành viên"}), 403
        if user_id == grp["owner_id"]:
            return jsonify({"error": "Chủ nhóm không thể rời nhóm, hãy xóa nhóm"}), 400

        cur = conn.execute(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id)
        )
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"error": "Người này không ở trong nhóm"}), 404
        remaining = _member_ids(conn, group_id)
    finally:
        conn.close()

    _notify(remaining + [user_id], group_id)
    return jsonify({"message": "Đã cập nhật thành viên"})


def delete_group(group_id):
    """DELETE /api/groups/<id> - chỉ chủ nhóm. Xóa luôn toàn bộ tin nhắn của nhóm."""
    conn = get_db()
    try:
        grp = conn.execute("SELECT owner_id FROM groups WHERE id = ?", (group_id,)).fetchone()
        if grp is None:
            return jsonify({"error": "Không tìm thấy nhóm"}), 404
        if grp["owner_id"] != g.user_id:
            return jsonify({"error": "Chỉ chủ nhóm mới xóa được nhóm"}), 403

        members = _member_ids(conn, group_id)
        conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))   # cascade
        conn.commit()
    finally:
        conn.close()

    _notify(members, group_id)
    return jsonify({"message": "Đã xóa nhóm"})
