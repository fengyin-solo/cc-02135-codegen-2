"""数据库操作"""
import sqlite3
import hashlib
from config import DB_FILE


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库表"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS share_links (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            created_by TEXT NOT NULL,
            expires_at REAL,
            max_downloads INTEGER,
            download_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        )
    ''')

    # 传输审计与操作留痕：文件接收、取件、授权、删除、导出均落表归档
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            actor_type TEXT NOT NULL DEFAULT 'guest',
            actor TEXT,
            actor_ip TEXT,
            object_type TEXT,
            object_id TEXT,
            object_name TEXT,
            result TEXT NOT NULL,
            detail TEXT,
            occurred_at TIMESTAMP NOT NULL DEFAULT (datetime('now', 'localtime'))
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred ON audit_logs(id DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor)')

    default_users = [
        ('admin', hashlib.sha256('admin123'.encode()).hexdigest()),
        ('user', hashlib.sha256('user123'.encode()).hexdigest()),
        ('test', hashlib.sha256('test123'.encode()).hexdigest())
    ]
    for username, password_hash in default_users:
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )

    conn.commit()
    conn.close()
