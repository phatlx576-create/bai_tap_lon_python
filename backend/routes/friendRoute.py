from flask import Blueprint

from controllers.friendController import (
    accept_request,
    decline_request,
    list_friends,
    list_requests,
    remove_friend,
    send_request,
)
from middlewares.authMiddleware import token_required

friend_bp = Blueprint("friends", __name__)

# Được gắn với prefix /api/friends trong server.py. Tất cả route đều yêu cầu đăng nhập.
friend_bp.add_url_rule("", endpoint="list", view_func=token_required(list_friends), methods=["GET"])
friend_bp.add_url_rule("/request", endpoint="send", view_func=token_required(send_request), methods=["POST"])
friend_bp.add_url_rule("/requests", endpoint="requests", view_func=token_required(list_requests), methods=["GET"])
friend_bp.add_url_rule("/<int:request_id>/accept", endpoint="accept", view_func=token_required(accept_request), methods=["POST"])
friend_bp.add_url_rule("/<int:request_id>/decline", endpoint="decline", view_func=token_required(decline_request), methods=["POST"])
friend_bp.add_url_rule("/<int:user_id>", endpoint="remove", view_func=token_required(remove_friend), methods=["DELETE"])