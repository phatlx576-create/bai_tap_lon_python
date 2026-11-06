from flask import Blueprint

from controllers.authController import login, register

auth_bp = Blueprint("auth", __name__)

# Được gắn với prefix /api/auth trong server.py
auth_bp.add_url_rule("/register", view_func=register, methods=["POST"])
auth_bp.add_url_rule("/login", view_func=login, methods=["POST"])
