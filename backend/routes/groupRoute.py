from flask import Blueprint

from controllers.groupController import (
    add_member,
    create_group,
    delete_group,
    list_groups,
    remove_member,
)
from middlewares.authMiddleware import token_required

group_bp = Blueprint("groups", __name__)

# Được gắn với prefix /api/groups trong server.py. Tất cả route đều yêu cầu đăng nhập.
group_bp.add_url_rule("", endpoint="list", view_func=token_required(list_groups), methods=["GET"])
group_bp.add_url_rule("", endpoint="create", view_func=token_required(create_group), methods=["POST"])
group_bp.add_url_rule("/<int:group_id>", endpoint="delete", view_func=token_required(delete_group), methods=["DELETE"])
group_bp.add_url_rule("/<int:group_id>/members", endpoint="add_member", view_func=token_required(add_member), methods=["POST"])
group_bp.add_url_rule(
    "/<int:group_id>/members/<int:user_id>",
    endpoint="remove_member",
    view_func=token_required(remove_member),
    methods=["DELETE"],
)
