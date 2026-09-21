"""Flask 应用入口"""
import logging
from flask import Flask, g, request
from flask_cors import CORS
from config import PORT
from database import init_db
from routes import auth_bp, files_bp, audit_bp
from audit import record_audit, infer_action, current_operator

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
CORS(app)

# 注册蓝图
app.register_blueprint(auth_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(files_bp)


@app.after_request
def audit_unauthorized(response):
    """对受保护端点的 401/403 拦截进行留痕（授权失败链路）"""
    if response.status_code not in (401, 403):
        return response

    # 业务层已经通过 audited_error 完成留痕的，不重复记录
    if g.get('audit_handled'):
        return response

    path = request.path or ''
    if not path.startswith('/api/'):
        return response

    # 公开端点的业务失败（文件不存在等）不走这里，只记录鉴权拦截
    protected = (
        '/api/download/', '/api/share', '/api/shares',
        '/api/files/', '/api/audit',
    )
    if not any(path.startswith(p) for p in protected):
        return response

    record_audit(
        infer_action(request.method, path), 'fail',
        operator=current_operator(),
        object_type='auth',
        object_name='受保护操作的身份校验',
        reason='未授权或token已过期' if response.status_code == 401 else '无权限执行此操作',
    )
    return response


# 初始化数据库（含审计表，兼容已有库）
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)
