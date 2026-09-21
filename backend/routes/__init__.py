"""路由模块"""
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)
files_bp = Blueprint('files', __name__)
audit_bp = Blueprint('audit', __name__)

from routes import auth_routes, file_routes, audit_routes
