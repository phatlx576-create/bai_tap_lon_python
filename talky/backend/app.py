import os
import re
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, or_
from werkzeug.security import check_password_hash, generate_password_hash

ORIGINS = os.environ.get("FRONTEND_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000").split(",")
SAMESITE = os.environ.get("COOKIE_SAMESITE", "Lax")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "hay-doi-khoa-bi-mat-nay"),
    SQLALCHEMY_DATABASE_URI="sqlite:///talky.db",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_SAMESITE=SAMESITE,
    SESSION_COOKIE_SECURE=SAMESITE == "None",
)
db = SQLAlchemy(app)
CORS(app, origins=ORIGINS, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*" if os.environ.get("PUBLIC") == "1" else ORIGINS)
online = {}
UPLOADS = os.path.join(app.root_path, "static", "uploads")
IMG_RE = re.compile(r"/static/uploads/[0-9a-f]{32}\.(png|jpg|jpeg|gif|webp)")


def now():
    return datetime.now(timezone.utc)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    pw = db.Column(db.String(200), nullable=False)

    def pub(self):
        return {"id": self.id, "username": self.username, "name": self.name,
                "online": self.id in online}


class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    to_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    accepted = db.Column(db.Boolean, default=False)


class Group(db.Model):
    __tablename__ = "chat_group"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)


class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("chat_group.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    last_read = db.Column(db.Integer, default=0)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    group_id = db.Column(db.Integer, db.ForeignKey("chat_group.id"))
    text = db.Column(db.Text, default="")
    img = db.Column(db.String(100))
    at = db.Column(db.DateTime, default=now)
    seen = db.Column(db.Boolean, default=False)

    def to_dict(self):
        sender = db.session.get(User, self.sender_id)
        return {"id": self.id, "from": self.sender_id, "to": self.receiver_id,
                "group": self.group_id, "sender": sender.name, "text": self.text,
                "img": self.img, "at": self.at.isoformat() + "Z", "seen": self.seen}


def is_member(uid, gid):
    return Member.query.filter_by(group_id=gid, user_id=uid).first()


def members_of(gid):
    return [m.user_id for m in Member.query.filter_by(group_id=gid).all()]


def me():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


def api(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = me()
        if not user:
            return jsonify(error="Bạn chưa đăng nhập"), 401
        return fn(user, *args, **kwargs)
    return wrapper


def relation(a, b):
    return Friend.query.filter(or_(
        and_(Friend.from_id == a, Friend.to_id == b),
        and_(Friend.from_id == b, Friend.to_id == a))).first()


def are_friends(a, b):
    r = relation(a, b)
    return bool(r and r.accepted)


def convo(a, b):
    return or_(and_(Message.sender_id == a, Message.receiver_id == b),
               and_(Message.sender_id == b, Message.receiver_id == a))


def refresh(*ids):
    for i in ids:
        socketio.emit("refresh", to=f"u{i}")


@app.get("/")
def index():
    return jsonify(app="Talky API", status="ok")


FRONTEND_DIR = os.path.join(os.path.dirname(app.root_path), "frontend")


@app.get("/web/")
@app.get("/web/<path:name>")
def web(name="index.html"):
    return send_from_directory(FRONTEND_DIR, name)


@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    username = str(d.get("username", "")).strip().lower()
    password = str(d.get("password", ""))
    name = str(d.get("name", "")).strip() or username
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
        return jsonify(error="Tên đăng nhập gồm 3-20 ký tự: chữ thường, số hoặc _"), 400
    if len(password) < 6:
        return jsonify(error="Mật khẩu cần ít nhất 6 ký tự"), 400
    if User.query.filter_by(username=username).first():
        return jsonify(error="Tên đăng nhập đã có người dùng"), 409
    user = User(username=username, name=name[:50], pw=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    session["uid"] = user.id
    return jsonify(user.pub())


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    user = User.query.filter_by(username=str(d.get("username", "")).strip().lower()).first()
    if not user or not check_password_hash(user.pw, str(d.get("password", ""))):
        return jsonify(error="Sai tên đăng nhập hoặc mật khẩu"), 401
    session["uid"] = user.id
    return jsonify(user.pub())


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
@api
def get_me(user):
    return jsonify(user.pub())


@app.get("/api/search")
@api
def search(user):
    q = request.args.get("q", "").strip().lower()
    if len(q) < 2:
        return jsonify([])
    found = User.query.filter(User.id != user.id, or_(
        User.username.contains(q), User.name.ilike(f"%{q}%"))).limit(10).all()
    out = []
    for x in found:
        r = relation(user.id, x.id)
        status = ("none" if not r else "friend" if r.accepted
                  else "sent" if r.from_id == user.id else "received")
        out.append({**x.pub(), "status": status})
    return jsonify(out)


@app.post("/api/friends/request")
@api
def friend_request(user):
    d = request.get_json(silent=True) or {}
    x = User.query.filter_by(username=str(d.get("username", ""))).first()
    if not x or x.id == user.id:
        return jsonify(error="Không tìm thấy người dùng"), 404
    r = relation(user.id, x.id)
    if r and (r.accepted or r.from_id == user.id):
        return jsonify(error="Đã là bạn hoặc đã gửi lời mời"), 409
    if r:
        r.accepted = True
    else:
        db.session.add(Friend(from_id=user.id, to_id=x.id))
    db.session.commit()
    refresh(user.id, x.id)
    return jsonify(ok=True)


@app.post("/api/friends/respond")
@api
def friend_respond(user):
    d = request.get_json(silent=True) or {}
    r = db.session.get(Friend, d.get("id"))
    if not r or r.to_id != user.id or r.accepted:
        return jsonify(error="Lời mời không hợp lệ"), 404
    other = r.from_id
    if d.get("accept"):
        r.accepted = True
    else:
        db.session.delete(r)
    db.session.commit()
    refresh(user.id, other)
    return jsonify(ok=True)


@app.get("/api/friends")
@api
def friends(user):
    rows = Friend.query.filter(or_(Friend.from_id == user.id, Friend.to_id == user.id)).all()
    fr, reqs, groups = [], [], []
    for r in rows:
        other = db.session.get(User, r.to_id if r.from_id == user.id else r.from_id)
        if r.accepted:
            last = Message.query.filter(convo(user.id, other.id)).order_by(Message.id.desc()).first()
            unread = Message.query.filter_by(sender_id=other.id, receiver_id=user.id, seen=False).count()
            fr.append({**other.pub(), "last": last.to_dict() if last else None, "unread": unread})
        elif r.to_id == user.id:
            reqs.append({**other.pub(), "id": r.id})
    for mem in Member.query.filter_by(user_id=user.id).all():
        g = db.session.get(Group, mem.group_id)
        last = Message.query.filter_by(group_id=g.id).order_by(Message.id.desc()).first()
        unread = Message.query.filter(Message.group_id == g.id, Message.id > mem.last_read,
                                      Message.sender_id != user.id).count()
        people = [db.session.get(User, i).pub() for i in members_of(g.id)]
        groups.append({"id": g.id, "name": g.name, "members": people,
                       "last": last.to_dict() if last else None, "unread": unread})
    return jsonify(friends=fr, requests=reqs, groups=groups)


@app.post("/api/groups")
@api
def create_group(user):
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()[:50]
    raw = d.get("members")
    ids = {i for i in (raw if isinstance(raw, list) else []) if isinstance(i, int) and are_friends(user.id, i)}
    if not name or not ids:
        return jsonify(error="Cần đặt tên nhóm và chọn ít nhất 1 người bạn"), 400
    g = Group(name=name)
    db.session.add(g)
    db.session.flush()
    for uid in ids | {user.id}:
        db.session.add(Member(group_id=g.id, user_id=uid))
    db.session.commit()
    refresh(user.id, *ids)
    return jsonify(id=g.id)


@app.post("/api/upload")
@api
def upload(user):
    f = request.files.get("file")
    ext = os.path.splitext(f.filename or "")[1].lower().lstrip(".") if f else ""
    if ext not in ("png", "jpg", "jpeg", "gif", "webp"):
        return jsonify(error="Chỉ gửi được ảnh png, jpg, gif hoặc webp"), 400
    os.makedirs(UPLOADS, exist_ok=True)
    name = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(UPLOADS, name))
    return jsonify(url=f"/static/uploads/{name}")


@app.errorhandler(413)
def too_big(_):
    return jsonify(error="Ảnh quá lớn, tối đa 5MB"), 413


@app.get("/api/messages/<kind>/<int:cid>")
@api
def messages(user, kind, cid):
    if kind == "g":
        if not is_member(user.id, cid):
            return jsonify(error="Bạn không ở trong nhóm này"), 403
        q = Message.query.filter_by(group_id=cid)
    elif kind == "u" and are_friends(user.id, cid):
        q = Message.query.filter(convo(user.id, cid))
    else:
        return jsonify(error="Hai bạn chưa là bạn bè"), 403
    before = request.args.get("before", type=int)
    if before:
        q = q.filter(Message.id < before)
    rows = q.order_by(Message.id.desc()).limit(30).all()[::-1]
    return jsonify(messages=[m.to_dict() for m in rows], more=len(rows) == 30)


def presence(uid, is_on):
    rows = Friend.query.filter(or_(Friend.from_id == uid, Friend.to_id == uid),
                               Friend.accepted.is_(True)).all()
    for r in rows:
        fid = r.to_id if r.from_id == uid else r.from_id
        socketio.emit("presence", {"id": uid, "online": is_on}, to=f"u{fid}")


@socketio.on("connect")
def on_connect(*_):
    uid = session.get("uid")
    if not uid:
        return False
    join_room(f"u{uid}")
    online[uid] = online.get(uid, 0) + 1
    if online[uid] == 1:
        presence(uid, True)


@socketio.on("disconnect")
def on_disconnect(*_):
    uid = session.get("uid")
    if not uid:
        return
    online[uid] = online.get(uid, 1) - 1
    if online[uid] <= 0:
        online.pop(uid, None)
        presence(uid, False)


def targets(uid, d):
    gid, to = d.get("group"), d.get("to")
    if isinstance(gid, int) and is_member(uid, gid):
        return members_of(gid), None, gid
    if isinstance(to, int) and are_friends(uid, to):
        return [uid, to], to, None
    return None


@socketio.on("send")
def on_send(d):
    uid = session.get("uid")
    d = d if isinstance(d, dict) else {}
    t = targets(uid, d) if uid else None
    text = str(d.get("text", "")).strip()[:2000]
    img = d.get("img")
    if img is not None and not (isinstance(img, str) and IMG_RE.fullmatch(img)):
        return {"ok": False}
    if not t or not (text or img):
        return {"ok": False}
    users, to, gid = t
    m = Message(sender_id=uid, receiver_id=to, group_id=gid, text=text, img=img)
    db.session.add(m)
    db.session.commit()
    data = m.to_dict()
    for i in users:
        emit("message", data, to=f"u{i}")
    return {"ok": True}


@socketio.on("typing")
def on_typing(d):
    uid = session.get("uid")
    t = targets(uid, d) if uid and isinstance(d, dict) else None
    if not t:
        return
    sender = db.session.get(User, uid)
    for i in t[0]:
        if i != uid:
            emit("typing", {"from": uid, "group": t[2], "name": sender.name}, to=f"u{i}")


@socketio.on("seen")
def on_seen(d):
    uid = session.get("uid")
    d = d if isinstance(d, dict) else {}
    if not uid:
        return
    gid, fid = d.get("group"), d.get("from")
    if isinstance(gid, int):
        mem = is_member(uid, gid)
        last = Message.query.filter_by(group_id=gid).order_by(Message.id.desc()).first()
        if mem and last and mem.last_read < last.id:
            mem.last_read = last.id
            db.session.commit()
            emit("refresh", to=f"u{uid}")
    elif isinstance(fid, int):
        n = Message.query.filter_by(sender_id=fid, receiver_id=uid, seen=False).update({"seen": True})
        db.session.commit()
        if n:
            emit("seen", {"by": uid}, to=f"u{fid}")
            emit("refresh", to=f"u{uid}")


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    socketio.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=5000,
                 debug=True, allow_unsafe_werkzeug=True)
