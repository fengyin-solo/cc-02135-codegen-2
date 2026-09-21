"""文件路由"""
import os
import re
import uuid
import time
import logging
from flask import request, jsonify, send_file, g
from werkzeug.utils import secure_filename
from routes import files_bp
from database import get_db
from auth import get_username_from_token, login_required
from config import UPLOAD_FOLDER, MAX_FILE_SIZE, BLOCKED_EXTENSIONS, SHARE_LINK_EXPIRE_HOURS, SHARE_LINK_MAX_DOWNLOADS
from audit import (
    record_audit,
    ACTION_RECEIVE, ACTION_PICKUP, ACTION_SHARE_PICKUP, ACTION_GRANT, ACTION_DELETE,
)

logger = logging.getLogger(__name__)


def audited_error(status_code, payload, **audit_kwargs):
    """构造一个已在业务层完成留痕的错误响应，避免 after_request 重复记录"""
    g.audit_handled = True
    record_audit(**audit_kwargs)
    return jsonify(payload), status_code


def allowed_file(filename):
    """检查文件扩展名是否被禁止"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext not in BLOCKED_EXTENSIONS


@files_bp.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return audited_error(
            400, {'error': '没有文件'},
            action=ACTION_RECEIVE, result='fail',
            object_type='file', object_name='上传请求',
            reason='请求中未携带文件'
        )

    file = request.files['file']
    if file.filename == '':
        return audited_error(
            400, {'error': '未选择文件'},
            action=ACTION_RECEIVE, result='fail',
            object_type='file', object_name='空文件名',
            reason='未选择文件'
        )

    if not allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        return audited_error(
            400, {'error': '不支持的文件类型'},
            action=ACTION_RECEIVE, result='fail',
            object_type='file', object_name=file.filename,
            detail={'extension': ext},
            reason=f'不支持的文件类型（.{ext} 被禁止上传）'
        )

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_FILE_SIZE:
        return audited_error(
            400, {'error': f'文件大小超过限制（最大{MAX_FILE_SIZE // 1024 // 1024}MB）'},
            action=ACTION_RECEIVE, result='fail',
            object_type='file', object_name=file.filename,
            detail={'size': file_size, 'limit': MAX_FILE_SIZE},
            reason=f'文件大小 {file_size} 字节超过限制 {MAX_FILE_SIZE} 字节'
        )

    file_id = str(uuid.uuid4())
    # 保留原始文件名用于显示（去掉路径分隔符防止注入）
    original_name = re.sub(r'[/\\]', '_', file.filename).strip()
    if not original_name:
        original_name = file_id

    # 磁盘上用 UUID + 扩展名存储，避免文件名编码问题
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    safe_filename = f"{file_id}.{ext}" if ext else file_id
    filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
    file.save(filepath)

    file_size = os.path.getsize(filepath)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO files (id, name, path, size) VALUES (?, ?, ?, ?)',
        (file_id, original_name, filepath, file_size)
    )
    conn.commit()
    conn.close()

    logger.info(f"文件上传成功: {original_name} (ID: {file_id}, 大小: {file_size} bytes)")
    # 采集链路：文件接收成功，身份与文件信息对齐
    record_audit(
        ACTION_RECEIVE, 'success',
        object_type='file', object_id=file_id, object_name=original_name,
        detail={'size': file_size, 'extension': ext or None}
    )
    return jsonify({'success': True, 'file_id': file_id, 'filename': original_name})


@files_bp.route('/api/files', methods=['GET'])
def list_files():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, path, size FROM files')
    files = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(files)


@files_bp.route('/api/files/<file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    """删除文件及其全部分享链接（需登录）"""
    operator = get_username_from_token(get_token_from_request())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, path FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        return audited_error(
            404, {'error': '文件不存在'},
            action=ACTION_DELETE, result='fail', operator=operator,
            object_type='file', object_id=file_id, object_name='未知文件',
            reason='目标文件不存在'
        )

    cursor.execute('DELETE FROM share_links WHERE file_id = ?', (file_id,))
    removed_shares = cursor.rowcount
    cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()

    disk_removed = False
    path = file_info['path']
    if path and os.path.exists(path) and os.path.abspath(path).startswith(
            os.path.abspath(UPLOAD_FOLDER)):
        try:
            os.remove(path)
            disk_removed = True
        except OSError as exc:
            # 数据库记录已删除，但磁盘文件残留：结果记为失败并说明原因
            record_audit(
                ACTION_DELETE, 'fail', operator=operator,
                object_type='file', object_id=file_id, object_name=file_info['name'],
                detail={'disk_path': path, 'removed_shares': removed_shares},
                reason=f'记录已删除但磁盘文件移除失败: {exc}'
            )
            return jsonify({'success': True, 'warning': '文件记录已删除，但磁盘文件移除失败'}), 200

    record_audit(
        ACTION_DELETE, 'success', operator=operator,
        object_type='file', object_id=file_id, object_name=file_info['name'],
        detail={'disk_removed': disk_removed, 'removed_shares': removed_shares}
    )
    logger.info(f"文件删除: {file_info['name']} (ID: {file_id}), 操作者 {operator}")
    return jsonify({'success': True, 'message': '文件已删除'})


@files_bp.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    # 优先从 Authorization 头获取 token，兼容查询参数（已废弃）
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
    else:
        token = request.args.get('token')  # 向后兼容，建议前端迁移到 Authorization 头

    if not token:
        return jsonify({'error': '未授权或token已过期'}), 401

    # 一步完成身份校验与操作者解析，保证审计里的身份与文件信息对得上
    username = get_username_from_token(token)
    if not username:
        return jsonify({'error': '未授权或token已过期'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, path FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()
    conn.close()

    if not file_info:
        return audited_error(
            404, {'error': '文件不存在'},
            action=ACTION_PICKUP, result='fail', operator=username,
            object_type='file', object_id=file_id, object_name='未知文件',
            reason='目标文件不存在'
        )

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        return audited_error(
            403, {'error': '非法文件路径'},
            action=ACTION_PICKUP, result='fail', operator=username,
            object_type='file', object_id=file_id, object_name=file_info['name'],
            reason='文件路径越权，已拒绝取件'
        )

    if not os.path.exists(file_info['path']):
        return audited_error(
            404, {'error': '文件不存在'},
            action=ACTION_PICKUP, result='fail', operator=username,
            object_type='file', object_id=file_id, object_name=file_info['name'],
            reason='文件记录存在但磁盘文件缺失'
        )

    logger.info(f"文件下载: {file_info['name']} (ID: {file_id})")
    record_audit(
        ACTION_PICKUP, 'success', operator=username,
        object_type='file', object_id=file_id, object_name=file_info['name']
    )
    return send_file(file_info['path'], as_attachment=True, download_name=file_info['name'])


def generate_short_id():
    """生成短的分享链接ID"""
    return uuid.uuid4().hex[:12]


def get_share_link_info(share_id):
    """获取分享链接信息，包含文件信息和有效性检查"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.id, s.file_id, s.created_by, s.expires_at, s.max_downloads, s.download_count, s.created_at,
               f.name as filename, f.size as filesize
        FROM share_links s
        JOIN files f ON s.file_id = f.id
        WHERE s.id = ?
    ''', (share_id,))
    share = cursor.fetchone()
    conn.close()
    return share


def is_share_valid(share):
    """检查分享链接是否有效"""
    if not share:
        return False, '分享链接不存在'

    if share['expires_at'] is not None and share['expires_at'] < time.time():
        return False, '分享链接已过期'

    if share['max_downloads'] is not None and share['download_count'] >= share['max_downloads']:
        return False, '分享链接下载次数已用完'

    return True, None


def increment_download_count(share_id):
    """增加下载次数"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE share_links SET download_count = download_count + 1 WHERE id = ?',
        (share_id,)
    )
    conn.commit()
    conn.close()


def get_token_from_request():
    """从请求中获取 token"""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return request.args.get('token')


@files_bp.route('/api/share', methods=['POST'])
@login_required
def create_share():
    """创建分享链接"""
    token = get_token_from_request()
    username = get_username_from_token(token)

    data = request.get_json()
    if not data:
        return jsonify({'error': '无效的请求数据'}), 400

    file_id = data.get('file_id', '').strip()
    expire_hours = data.get('expire_hours')
    max_downloads = data.get('max_downloads')

    if not file_id:
        return audited_error(
            400, {'error': '文件ID不能为空'},
            action=ACTION_GRANT, result='fail', operator=username,
            object_type='file', object_name='空文件ID',
            reason='创建分享链接时未提供文件ID'
        )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        return audited_error(
            404, {'error': '文件不存在'},
            action=ACTION_GRANT, result='fail', operator=username,
            object_type='file', object_id=file_id, object_name='未知文件',
            reason='无法为不存在的文件创建授权链接'
        )

    if expire_hours is None:
        expire_hours = SHARE_LINK_EXPIRE_HOURS

    if expire_hours < 0:
        expire_hours = None

    if expire_hours is not None:
        expires_at = time.time() + expire_hours * 3600
    else:
        expires_at = None

    if max_downloads is None:
        max_downloads = SHARE_LINK_MAX_DOWNLOADS

    if max_downloads < 0:
        max_downloads = None

    share_id = generate_short_id()

    cursor.execute('''
        INSERT INTO share_links (id, file_id, created_by, expires_at, max_downloads)
        VALUES (?, ?, ?, ?, ?)
    ''', (share_id, file_id, username, expires_at, max_downloads))

    conn.commit()
    conn.close()

    logger.info(f"分享链接创建成功: 文件 {file_info['name']}, 分享ID {share_id}, 创建者 {username}")
    record_audit(
        ACTION_GRANT, 'success', operator=username,
        object_type='share_link', object_id=share_id, object_name=file_info['name'],
        detail={
            'file_id': file_id,
            'expires_at': expires_at,
            'max_downloads': max_downloads,
        }
    )

    return jsonify({
        'success': True,
        'share_id': share_id,
        'expires_at': expires_at,
        'max_downloads': max_downloads,
        'filename': file_info['name']
    })


@files_bp.route('/api/share/<share_id>', methods=['GET'])
def get_share(share_id):
    """获取分享链接信息（公开访问）"""
    share = get_share_link_info(share_id)
    valid, error_msg = is_share_valid(share)

    if not share:
        return jsonify({'error': '分享链接不存在'}), 404

    share_data = {
        'share_id': share['id'],
        'filename': share['filename'],
        'filesize': share['filesize'],
        'created_by': share['created_by'],
        'expires_at': share['expires_at'],
        'max_downloads': share['max_downloads'],
        'download_count': share['download_count'],
        'created_at': share['created_at'],
        'is_valid': valid,
        'error_msg': error_msg
    }

    return jsonify(share_data)


@files_bp.route('/api/share/<share_id>/download', methods=['GET'])
def download_by_share(share_id):
    """通过分享链接下载文件（公开访问）"""
    share = get_share_link_info(share_id)
    valid, error_msg = is_share_valid(share)

    if not valid:
        filename = share['filename'] if share else None
        return audited_error(
            404, {'error': error_msg},
            action=ACTION_SHARE_PICKUP, result='fail',
            operator=(share['created_by'] if share else None),
            object_type='share_link', object_id=share_id, object_name=filename,
            detail={'downloader': 'anonymous'},
            reason=f'访客取件被拒绝：{error_msg}'
        )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, path FROM files WHERE id = ?', (share['file_id'],))
    file_info = cursor.fetchone()
    conn.close()

    if not file_info:
        return audited_error(
            404, {'error': '文件不存在'},
            action=ACTION_SHARE_PICKUP, result='fail',
            operator=share['created_by'],
            object_type='share_link', object_id=share_id, object_name='未知文件',
            detail={'file_id': share['file_id'], 'downloader': 'anonymous'},
            reason='分享链接对应的文件不存在'
        )

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        return audited_error(
            403, {'error': '非法文件路径'},
            action=ACTION_SHARE_PICKUP, result='fail',
            operator=share['created_by'],
            object_type='share_link', object_id=share_id, object_name=file_info['name'],
            detail={'downloader': 'anonymous'},
            reason='文件路径越权，已拒绝取件'
        )

    if not os.path.exists(file_info['path']):
        return audited_error(
            404, {'error': '文件不存在'},
            action=ACTION_SHARE_PICKUP, result='fail',
            operator=share['created_by'],
            object_type='share_link', object_id=share_id, object_name=file_info['name'],
            detail={'downloader': 'anonymous'},
            reason='文件记录存在但磁盘文件缺失'
        )

    increment_download_count(share_id)

    logger.info(f"分享下载: 文件 {file_info['name']}, 分享ID {share_id}, 下载次数 {share['download_count'] + 1}")
    record_audit(
        ACTION_SHARE_PICKUP, 'success',
        operator=share['created_by'],
        object_type='share_link', object_id=share_id, object_name=file_info['name'],
        detail={
            'file_id': share['file_id'],
            'downloader': 'anonymous',
            'download_count': share['download_count'] + 1,
        }
    )
    return send_file(file_info['path'], as_attachment=True, download_name=file_info['name'])


@files_bp.route('/api/shares', methods=['GET'])
@login_required
def list_shares():
    """获取当前用户的所有分享链接"""
    token = get_token_from_request()
    username = get_username_from_token(token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.id, s.file_id, s.created_by, s.expires_at, s.max_downloads, s.download_count, s.created_at,
               f.name as filename, f.size as filesize
        FROM share_links s
        JOIN files f ON s.file_id = f.id
        WHERE s.created_by = ?
        ORDER BY s.created_at DESC
    ''', (username,))
    shares = cursor.fetchall()
    conn.close()

    result = []
    for share in shares:
        valid, error_msg = is_share_valid(share)
        result.append({
            'share_id': share['id'],
            'file_id': share['file_id'],
            'filename': share['filename'],
            'filesize': share['filesize'],
            'expires_at': share['expires_at'],
            'max_downloads': share['max_downloads'],
            'download_count': share['download_count'],
            'created_at': share['created_at'],
            'is_valid': valid,
            'error_msg': error_msg
        })

    return jsonify(result)


@files_bp.route('/api/share/<share_id>', methods=['DELETE'])
@login_required
def delete_share(share_id):
    """删除分享链接"""
    token = get_token_from_request()
    username = get_username_from_token(token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT created_by, file_id FROM share_links WHERE id = ?', (share_id,))
    share = cursor.fetchone()

    if not share:
        conn.close()
        return audited_error(
            404, {'error': '分享链接不存在'},
            action=ACTION_DELETE, result='fail', operator=username,
            object_type='share_link', object_id=share_id, object_name='未知分享链接',
            reason='目标分享链接不存在'
        )

    if share['created_by'] != username:
        conn.close()
        return audited_error(
            403, {'error': '无权限删除此分享链接'},
            action=ACTION_DELETE, result='fail', operator=username,
            object_type='share_link', object_id=share_id,
            detail={'owner': share['created_by']},
            reason=f'操作者 {username} 非链接创建者 {share["created_by"]}'
        )

    cursor.execute('DELETE FROM share_links WHERE id = ?', (share_id,))
    conn.commit()
    conn.close()

    logger.info(f"分享链接删除: 分享ID {share_id}, 文件ID {share['file_id']}, 操作者 {username}")
    record_audit(
        ACTION_DELETE, 'success', operator=username,
        object_type='share_link', object_id=share_id,
        detail={'file_id': share['file_id']},
        object_name=f'分享链接 {share_id}'
    )
    return jsonify({'success': True, 'message': '分享链接已删除'})
