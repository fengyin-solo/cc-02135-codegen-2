"""Flask 应用入口"""
import logging
from flask import Flask
from flask_cors import CORS
from config import PORT
from database import init_db
from routes import auth_bp, files_bp, audit_bp

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
CORS(app)

# 注册蓝图
app.register_blueprint(auth_bp)
app.register_blueprint(files_bp)
app.register_blueprint(audit_bp)

# 初始化数据库
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)
