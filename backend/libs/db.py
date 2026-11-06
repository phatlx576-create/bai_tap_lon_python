import os
import sqlite3

# File database nằm trong thư mục backend/
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chat.db")


def get_db():
    """Mở kết nối tới SQLite. Mỗi request/socket event nên mở và đóng 1 kết nối."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # truy cập cột bằng tên: row["username"]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _add_column(conn, table, column, ddl):
    """Nâng cấp DB cũ: thêm cột nếu chưa có."""
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db():
    """Tạo các bảng nếu chưa tồn tại. Gọi 1 lần khi khởi động server."""
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            public_key    TEXT    NOT NULL,   -- khóa công khai ECDH (JSON/base64)
            created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS friends (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status       TEXT    NOT NULL DEFAULT 'pending',  -- pending | accepted
            created_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (requester_id, receiver_id),
            CHECK (requester_id != receiver_id)
        );

        -- Tin nhắn 1-1. Server chỉ thấy bản mã.
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            kind        TEXT    NOT NULL DEFAULT 'text',   -- text | file | system
            ciphertext  TEXT    NOT NULL,     -- bản mã AES-GCM (base64)
            iv          TEXT    NOT NULL,     -- vector khởi tạo (base64)
            meta        TEXT,                 -- (file) tên/loại/kích thước, cũng đã mã hóa
            read_at     TEXT,                 -- thời điểm người nhận đã xem
            deleted_at  TEXT,                 -- không NULL = đã thu hồi
            created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_messages_pair
            ON messages (sender_id, receiver_id, created_at);

        -- "Xóa với tôi": ẩn tin nhắn khỏi lịch sử của riêng một người
        CREATE TABLE IF NOT EXISTS hidden_messages (
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            scope      TEXT    NOT NULL,      -- dm | group
            message_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, scope, message_id)
        );

        -- Chat nhóm
        CREATE TABLE IF NOT EXISTS groups (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        -- Mỗi thành viên giữ khóa nhóm đã được "gói" (mã hóa) riêng cho họ
        CREATE TABLE IF NOT EXISTS group_members (
            group_id      INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role          TEXT    NOT NULL DEFAULT 'member',   -- owner | member
            wrapper_id    INTEGER NOT NULL REFERENCES users(id),
            key_ct        TEXT    NOT NULL,
            key_iv        TEXT    NOT NULL,
            joined_msg_id INTEGER NOT NULL DEFAULT 0,  -- chỉ thấy tin từ id này trở đi
            joined_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS group_messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            sender_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            kind       TEXT    NOT NULL DEFAULT 'text',
            ciphertext TEXT    NOT NULL,
            iv         TEXT    NOT NULL,
            meta       TEXT,
            deleted_at TEXT,
            created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_group_messages
            ON group_messages (group_id, id);
        """
    )

    # Nâng cấp database cũ (tạo từ các phiên bản trước)
    _add_column(conn, "messages", "read_at", "TEXT")
    _add_column(conn, "messages", "kind", "TEXT NOT NULL DEFAULT 'text'")
    _add_column(conn, "messages", "meta", "TEXT")
    _add_column(conn, "messages", "deleted_at", "TEXT")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Đã tạo database tại:", DB_PATH)
