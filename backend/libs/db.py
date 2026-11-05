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

        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ciphertext  TEXT    NOT NULL,     -- bản mã AES-GCM (base64)
            iv          TEXT    NOT NULL,     -- vector khởi tạo (base64)
            created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_messages_pair
            ON messages (sender_id, receiver_id, created_at);
        """
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Đã tạo database tại:", DB_PATH)