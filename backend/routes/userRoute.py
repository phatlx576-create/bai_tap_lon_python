from flask import Blueprint

from controllers.userController import get_me, get_public_key, search_users
from middlewares.authMiddleware import token_required

user_bp = Blueprint("users", __name__)

# Được gắn với prefix /api/users trong server.py
# Tất cả route đều yêu cầu đăng nhập
user_bp.add_url_rule("/me", view_func=token_required(get_me), methods=["GET"])
user_bp.add_url_rule("/search", view_func=token_required(search_users), methods=["GET"])
user_bp.add_url_rule(
    "/<int:user_id>/public-key",
    view_func=token_required(get_public_key),
    methods=["GET"],
)
