"""传输审计与操作留痕

把文件接收（上传）、取件（下载/分享下载）、授权（登录鉴权）、
删除（撤销分享）、审计导出等动作统一写为审计记录。

同一条业务操作与其涉及的身份、文件信息在同一次写入中落库，
保证“身份与文件信息对得上”；审计表只追加、不修改，
配合自增主键保证历史顺序与总数稳定。
"""
import json
import logging
import sqlite3
from flask import request
from database import get_db

logger = logging.getLogger(__name__)

# 动作常量（值即落库与对外展示的稳定标识）
ACTION_AUTH = 'auth'                # 身份授权（登录）
ACTION_UPLOAD = 'upload'            # 文件接收
ACTION_DOWNLOAD = 'download'        # 登录取件
ACTION_SHARE_DOWNLOAD = 'share_download'  # 分享链接取件
ACTION_SHARE_CREATE = 'share_create'      # 创建分享授权
ACTION_SHARE_DELETE = 'share_delete'      # 删除/撤销分享
ACTION_AUDIT_EXPORT = 'audit_export'      # 审计文件导出

RESULT_SUCCESS = 'success'
RESULT_FAILURE = 'failure'

# 动作 -> 中文展示名
ACTION_LABELS = {
    ACTION_AUTH: '身份授权',
    ACTION_UPLOAD: '文件接收',
    ACTION_DOWNLOAD: '文件取件',
    ACTION_SHARE_DOWNLOAD: '分享取件',
    ACTION_SHARE_CREATE: '创建分享',
    ACTION_SHARE_DELETE: '删除分享',
    ACTION_AUDIT_EXPORT: '审计导出',
}


def record_audit(action, result, *, actor=None, actor_type=None,
                 object_type=None, object_id=None, object_name=None,
                 detail=None, conn=None, commit=True):
    """写入一条审计记录。

    - 传入 conn 时复用调用方的数据库连接，可与业务数据在同一事务内提交，
      保证操作结果与留痕一致；不传则使用独立连接。
    - 审计写入本身不应影响主业务：发生异常时只记录日志、不抛出。
    """
    own_conn = conn is None
    if own_conn:
        conn = get_db()

    # 操作者类型：登录用户 / 访客（分享链接取件等匿名场景）
    if actor_type is None:
        actor_type = 'user' if actor else 'guest'

    if isinstance(detail, (dict, list)):
        detail_text = json.dumps(detail, ensure_ascii=False)
    elif detail is None:
        detail_text = None
    else:
        detail_text = str(detail)

    actor_ip = None
    try:
        actor_ip = request.remote_addr if request else None
    except RuntimeError:
        actor_ip = None

    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs
                (action, actor_type, actor, actor_ip,
                 object_type, object_id, object_name, result, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            action, actor_type, actor, actor_ip,
            object_type, object_id, object_name, result, detail_text
        ))
        if commit:
            conn.commit()
        return cursor.lastrowid
    except sqlite3.Error:
        logger.exception('审计记录写入失败: action=%s object=%s', action, object_id)
        if commit:
            conn.rollback()
        return None
    finally:
        if own_conn:
            conn.close()


def query_audit_logs(*, action=None, actor=None, result=None,
                     keyword=None, limit=20, offset=0, conn=None):
    """按条件查询审计记录，返回 (records, total)。

    total 为过滤条件下的总数，与分页无关，保证翻页时总数稳定。
    排序固定为 id DESC（最新在前），历史顺序不随重复查询变化。
    """
    own_conn = conn is None
    if own_conn:
        conn = get_db()

    where = []
    params = []
    if action:
        where.append('action = ?')
        params.append(action)
    if actor:
        where.append('actor = ?')
        params.append(actor)
    if result:
        where.append('result = ?')
        params.append(result)
    if keyword:
        where.append('(object_name LIKE ? OR object_id LIKE ? OR actor LIKE ? OR detail LIKE ?)')
        like = f'%{keyword}%'
        params.extend([like, like, like, like])

    where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''

    cursor = conn.cursor()
    cursor.execute(f'SELECT COUNT(*) AS cnt FROM audit_logs{where_sql}', params)
    total = cursor.fetchone()['cnt']

    query_params = list(params) + [int(limit), int(offset)]
    cursor.execute(f'''
        SELECT id, action, actor_type, actor, actor_ip,
               object_type, object_id, object_name, result, detail, occurred_at
        FROM audit_logs
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    ''', query_params)
    rows = [dict(row) for row in cursor.fetchall()]

    if own_conn:
        conn.close()
    return rows, total


def get_audit_logs_by_ids(log_ids, *, conn=None):
    """按 ID 集合取回审计记录，顺序固定 id DESC，供导出使用。"""
    if not log_ids:
        return []

    own_conn = conn is None
    if own_conn:
        conn = get_db()

    placeholders = ','.join('?' for _ in log_ids)
    cursor = conn.cursor()
    cursor.execute(f'''
        SELECT id, action, actor_type, actor, actor_ip,
               object_type, object_id, object_name, result, detail, occurred_at
        FROM audit_logs
        WHERE id IN ({placeholders})
        ORDER BY id DESC
    ''', [int(x) for x in log_ids])
    rows = [dict(row) for row in cursor.fetchall()]

    if own_conn:
        conn.close()
    return rows
