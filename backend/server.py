import os

from flask import Flask, send_from_directory
from flask_cors import CORS

from libs.db import init_db
from libs.socket import socketio

# Các blueprint sẽ viết ở các bước sau
from routes.authRoute import auth_bp
from routes.userRoute import user_bp
from routes.friendRoute import friend_bp

# Import để đăng ký các sự kiện socket (join, send_message, ...)
import sockets.chatSocket  # noqa: F401

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")


def create_app():
    app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "doi-khoa-bi-mat-nay-khi-nop-bai")

    CORS(app)

    # REST API
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(user_bp, url_prefix="/api/users")
    app.register_blueprint(friend_bp, url_prefix="/api/friends")

    # Phục vụ giao diện: mở http://localhost:5000
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")
    return app


app = create_app()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"Server chạy tại http://localhost:{port}")
    # KHÔNG bật debug khi mở ra internet. Khi cần debug ở máy mình: đặt DEBUG=1
    debug = os.environ.get("DEBUG") == "1"
    socketio.run(app, host="0.0.0.0", port=port, debug=debug, allow_unsafe_werkzeug=True)