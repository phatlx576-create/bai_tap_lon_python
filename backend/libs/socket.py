from flask_socketio import SocketIO

# Tạo 1 instance dùng chung. Gắn vào Flask app ở server.py (socketio.init_app).
# Đặt ở đây để chatSocket.py và server.py cùng import mà không bị import vòng.
socketio = SocketIO()

# Theo dõi user đang online: user_id -> set các sid (1 user có thể mở nhiều tab)
online_users = {}
