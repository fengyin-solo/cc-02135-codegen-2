"""认证路由"""
import time
import logging
from flask import request, jsonify
from routes import auth_bp
from auth import rate_limit, generate_token, refresh_token as do_refresh_token, authenticate_user
from audit import record_audit, ACTION_AUTH

logger = logging.getLogger(__name__)


@auth_bp.route('/api/auth', methods=['POST'])
@rate_limit
def authenticate():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': '无效的请求数据'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        record_audit(
            ACTION_AUTH, 'fail', operator=username or None,
            object_type='auth', object_name='账号登录',
            reason='用户名或密码为空'
        )
        return jsonify({'success': False, 'error': '用户名和密码不能为空'}), 400

    if len(username) > 50 or len(password) > 100:
        record_audit(
            ACTION_AUTH, 'fail', operator=username,
            object_type='auth', object_name='账号登录',
            reason='输入长度超出限制'
        )
        return jsonify({'success': False, 'error': '输入长度超出限制'}), 400

    if authenticate_user(username, password):
        token = generate_token(username)
        logger.info(f"用户认证成功: {username}")
        record_audit(
            ACTION_AUTH, 'success', operator=username,
            object_type='auth', object_name=f'账号 {username} 登录'
        )
        return jsonify({'success': True, 'token': token})

    logger.warning(f"用户认证失败: {username}")
    record_audit(
        ACTION_AUTH, 'fail', operator=username,
        object_type='auth', object_name=f'账号 {username} 登录',
        reason='用户名或密码错误'
    )
    time.sleep(0.5)
    return jsonify({'success': False, 'error': '用户名或密码错误'}), 401


@auth_bp.route('/api/refresh-token', methods=['POST'])
def refresh_token_endpoint():
    token = request.args.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token:
        return jsonify({'error': '缺少token'}), 400

    if do_refresh_token(token):
        return jsonify({'success': True, 'message': 'Token已刷新'})

    return jsonify({'error': 'Token无效或已过期'}), 401
