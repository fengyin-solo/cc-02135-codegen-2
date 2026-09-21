"""审计留痕模块

把文件接收（上传采集）、取件（登录下载/分享下载）、授权（分享链接）、
删除、登录验证与审计导出等动作整理为审计记录，联通登录身份与操作对象。

约定：
- 审计写入失败只记录日志，绝不影响主业务流程；
- 审计记录只追加、不修改、不删除，保证历史顺序与总数稳定。
"""
import json
import time
import logging
from datetime import datetime, timezone

from flask import request

from database import get_db

logger = logging.getLogger(__name__)

# ---- 动作类型 ----
ACTION_AUTH = 'auth'                   # 登录验证 / 授权拦截
ACTION_RECEIVE = 'receive'             # 文件接收（上传采集）
ACTION_PICKUP = 'pickup'               # 取件（登录后下载）
ACTION_SHARE_PICKUP = 'share_pickup'   # 分享取件（访客通过链接下载）
ACTION_GRANT = 'grant'                 # 授权（创建分享链接）
ACTION_DELETE = 'delete'               # 删除（文件 / 分享链接）
ACTION_EXPORT = 'export'               # 审计记录导出

ACTION_LABELS = {
    ACTION_AUTH: '登录验证',
    ACTION_RECEIVE: '文件接收',
    ACTION_PICKUP: '取件',
    ACTION_SHARE_PICKUP: '分享取件',
    ACTION_GRANT: '授权',
    ACTION_DELETE: '删除',
    ACTION_EXPORT: '审计导出',
}

VALID_ACTIONS = set(ACTION_LABELS)
VALID_RESULTS = {'success', 'fail'}

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


def get_client_ip():
    """获取来访者 IP，优先取反向代理转发链中的第一个地址"""
    try:
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        return request.remote_addr
    except RuntimeError:
        # 脱离请求上下文调用
        return None


def extract_token():
    """从 Authorization 头或查询参数中提取 token"""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return request.args.get('token')


def current_operator():
    """尽力解析当前请求对应的登录用户名，未登录返回 None"""
    token = extract_token()
    if not token:
        return None
    # 延迟导入，避免与 auth 模块产生导入期循环依赖
    from auth import get_username_from_token
    try:
        return get_username_from_token(token)
    except Exception:
        logger.exception('解析操作者身份失败')
        return None


def infer_action(method, path):
    """根据被拦截的受保护端点推断动作类型（用于 401/403 未授权留痕）"""
    if path.endswith('/audit/export') or path.endswith('/audit-logs'):
        return ACTION_EXPORT
    if path.startswith('/api/download/'):
        return ACTION_PICKUP
    if method.upper() == 'DELETE' and (
            path.startswith('/api/share/') or path.startswith('/api/files/')):
        return ACTION_DELETE
    if path.rstrip('/').endswith('/share') or path.endswith('/shares'):
        return ACTION_GRANT
    return ACTION_AUTH


def record_audit(action, result, *, operator=None, object_type=None, object_id=None,
                 object_name=None, detail=None, reason=None):
    """写入一条审计记录（只追加）。任何异常都被吞掉并写日志，不影响业务。

    返回新记录 id；写入失败返回 None。
    """
    if action not in VALID_ACTIONS:
        logger.warning('未知审计动作类型: %s', action)
        action = ACTION_AUTH
    if result not in VALID_RESULTS:
        result = 'fail'

    detail_text = None
    if detail is not None:
        try:
            detail_text = detail if isinstance(detail, str) else json.dumps(
                detail, ensure_ascii=False)
        except (TypeError, ValueError):
            detail_text = str(detail)

    now = time.time()
    created_at = datetime.fromtimestamp(now, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs
                (action, result, operator, object_type, object_id, object_name,
                 detail, reason, ip, created_at, created_ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            action, result, operator, object_type,
            str(object_id) if object_id is not None else None,
            object_name, detail_text, reason, get_client_ip(), created_at, now
        ))
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()
        return new_id
    except Exception:
        logger.exception('写入审计记录失败')
        return None


def _row_to_dict(row):
    item = dict(row)
    if item.get('detail'):
        try:
            item['detail'] = json.loads(item['detail'])
        except (ValueError, TypeError):
            pass
    return item


def _normalize_pagination(page, page_size):
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(page_size)
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    page_size = min(MAX_PAGE_SIZE, max(1, page_size))
    return page, page_size


def query_audit_logs(action=None, result=None, keyword=None, page=1, page_size=DEFAULT_PAGE_SIZE):
    """按动作/结果/关键字筛选审计记录，固定按时间倒序、ID 倒序分页。

    返回 (items, total, page, page_size)。当请求页超出范围时回退到最后一页。
    """
    page, page_size = _normalize_pagination(page, page_size)

    where = []
    params = []
    if action in VALID_ACTIONS:
        where.append('action = ?')
        params.append(action)
    if result in VALID_RESULTS:
        where.append('result = ?')
        params.append(result)
    if keyword:
        like = f'%{keyword.strip()}%'
        where.append(
            '(operator LIKE ? OR object_name LIKE ? OR object_id LIKE ? '
            'OR reason LIKE ? OR detail LIKE ?)'
        )
        params.extend([like, like, like, like, like])

    where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f'SELECT COUNT(*) AS cnt FROM audit_logs{where_sql}', params)
    total = cursor.fetchone()['cnt']

    if total > 0:
        max_page = (total + page_size - 1) // page_size
        if page > max_page:
            page = max_page

    cursor.execute(
        f'''SELECT id, action, result, operator, object_type, object_id, object_name,
                  detail, reason, ip, created_at, created_ts
           FROM audit_logs{where_sql}
           ORDER BY created_ts DESC, id DESC
           LIMIT ? OFFSET ?''',
        (*params, page_size, (page - 1) * page_size)
    )
    items = [_row_to_dict(row) for row in cursor.fetchall()]
    conn.close()
    return items, total, page, page_size


def get_audit_logs_by_ids(ids):
    """按 ID 集合取审计记录，保持与列表一致的倒序；不存在的 ID 被自然跳过"""
    if not ids:
        return []
    placeholders = ','.join('?' for _ in ids)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        f'''SELECT id, action, result, operator, object_type, object_id, object_name,
                  detail, reason, ip, created_at, created_ts
           FROM audit_logs WHERE id IN ({placeholders})
           ORDER BY created_ts DESC, id DESC''',
        tuple(ids)
    )
    items = [_row_to_dict(row) for row in cursor.fetchall()]
    conn.close()
    return items
