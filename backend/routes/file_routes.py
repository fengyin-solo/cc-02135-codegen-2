"""文件路由"""
import os
import re
import uuid
import time
import logging
from flask import request, jsonify, send_file
from routes import files_bp
from database import get_db
from auth import verify_token, get_username_from_token, login_required
from audit import (
    record_audit,
    ACTION_UPLOAD, ACTION_DOWNLOAD, ACTION_SHARE_DOWNLOAD,
    ACTION_SHARE_CREATE, ACTION_SHARE_DELETE,
    RESULT_SUCCESS, RESULT_FAILURE,
)
from config import UPLOAD_FOLDER, MAX_FILE_SIZE, BLOCKED_EXTENSIONS, SHARE_LINK_EXPIRE_HOURS, SHARE_LINK_MAX_DOWNLOADS

logger = logging.getLogger(__name__)


def allowed_file(filename):
    """检查文件扩展名是否被禁止"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext not in BLOCKED_EXTENSIONS


@files_bp.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': '没有文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '未选择文件'}), 400

    raw_name = file.filename
    if not allowed_file(raw_name):
        record_audit(
            ACTION_UPLOAD, RESULT_FAILURE,
            object_type='file', object_name=re.sub(r'[/\\]', '_', raw_name),
            detail={'reason': 'blocked_extension',
                    'extension': raw_name.rsplit('.', 1)[1].lower() if '.' in raw_name else ''}
        )
        return jsonify({'error': '不支持的文件类型'}), 400

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_FILE_SIZE:
        record_audit(
            ACTION_UPLOAD, RESULT_FAILURE,
            object_type='file', object_name=re.sub(r'[/\\]', '_', raw_name),
            detail={'reason': 'file_too_large', 'size': file_size, 'limit': MAX_FILE_SIZE}
        )
        return jsonify({'error': f'文件大小超过限制（最大{MAX_FILE_SIZE // 1024 // 1024}MB）'}), 400

    file_id = str(uuid.uuid4())
    # 保留原始文件名用于显示（去掉路径分隔符防止注入）
    original_name = re.sub(r'[/\\]', '_', raw_name).strip()
    if not original_name:
        original_name = file_id

    # 磁盘上用 UUID + 扩展名存储，避免文件名编码问题
    ext = raw_name.rsplit('.', 1)[1].lower() if '.' in raw_name else ''
    safe_filename = f"{file_id}.{ext}" if ext else file_id
    filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
    file.save(filepath)

    file_size = os.path.getsize(filepath)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO files (id, name, path, size) VALUES (?, ?, ?, ?)',
            (file_id, original_name, filepath, file_size)
        )
        # 与文件元数据同一事务留痕，保证文件信息与审计记录对得上
        record_audit(
            ACTION_UPLOAD, RESULT_SUCCESS,
            object_type='file', object_id=file_id, object_name=original_name,
            detail={'size': file_size}, conn=conn, commit=False
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        # 落库失败时清理已写入磁盘的文件
        if os.path.exists(filepath):
            os.remove(filepath)
        raise
    conn.close()

    logger.info(f"文件上传成功: {original_name} (ID: {file_id}, 大小: {file_size} bytes)")
    return jsonify({'success': True, 'file_id': file_id, 'filename': original_name})


@files_bp.route('/api/files', methods=['GET'])
def list_files():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, path, size FROM files')
    files = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(files)


@files_bp.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    # 优先从 Authorization 头获取 token，兼容查询参数（已废弃）
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
    else:
        token = request.args.get('token')  # 向后兼容，建议前端迁移到 Authorization 头

    if not token or not verify_token(token):
        record_audit(
            ACTION_DOWNLOAD, RESULT_FAILURE,
            object_type='file', object_id=file_id,
            detail={'reason': 'unauthorized'}
        )
        return jsonify({'error': '未授权或token已过期'}), 401

    username = get_username_from_token(token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, path FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        record_audit(
            ACTION_DOWNLOAD, RESULT_FAILURE, actor=username,
            object_type='file', object_id=file_id,
            detail={'reason': 'file_not_found'}
        )
        return jsonify({'error': '文件不存在'}), 404

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        conn.close()
        record_audit(
            ACTION_DOWNLOAD, RESULT_FAILURE, actor=username,
            object_type='file', object_id=file_id, object_name=file_info['name'],
            detail={'reason': 'invalid_path'}
        )
        return jsonify({'error': '非法文件路径'}), 403

    if not os.path.exists(file_info['path']):
        conn.close()
        record_audit(
            ACTION_DOWNLOAD, RESULT_FAILURE, actor=username,
            object_type='file', object_id=file_id, object_name=file_info['name'],
            detail={'reason': 'file_missing_on_disk'}
        )
        return jsonify({'error': '文件不存在'}), 404

    conn.close()
    record_audit(
        ACTION_DOWNLOAD, RESULT_SUCCESS, actor=username,
        object_type='file', object_id=file_id, object_name=file_info['name'],
        detail={'channel': 'authenticated'}
    )

    logger.info(f"文件下载: {file_info['name']} (ID: {file_id})")
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
    data = request.get_json()
    if not data:
        return jsonify({'error': '无效的请求数据'}), 400

    file_id = data.get('file_id', '').strip()
    expire_hours = data.get('expire_hours')
    max_downloads = data.get('max_downloads')

    token = get_token_from_request()
    username = get_username_from_token(token)

    if not file_id:
        return jsonify({'error': '文件ID不能为空'}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        record_audit(
            ACTION_SHARE_CREATE, RESULT_FAILURE, actor=username,
            object_type='file', object_id=file_id,
            detail={'reason': 'file_not_found'}
        )
        return jsonify({'error': '文件不存在'}), 404

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

    try:
        cursor.execute('''
            INSERT INTO share_links (id, file_id, created_by, expires_at, max_downloads)
            VALUES (?, ?, ?, ?, ?)
        ''', (share_id, file_id, username, expires_at, max_downloads))
        # 授权与文件信息同事务留痕
        record_audit(
            ACTION_SHARE_CREATE, RESULT_SUCCESS, actor=username,
            object_type='share_link', object_id=share_id, object_name=file_info['name'],
            detail={'file_id': file_id,
                    'expire_hours': expire_hours,
                    'max_downloads': max_downloads},
            conn=conn, commit=False
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    conn.close()

    logger.info(f"分享链接创建成功: 文件 {file_info['name']}, 分享ID {share_id}, 创建者 {username}")

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
        record_audit(
            ACTION_SHARE_DOWNLOAD, RESULT_FAILURE,
            object_type='share_link', object_id=share_id,
            detail={'reason': error_msg or 'invalid_share'}
        )
        return jsonify({'error': error_msg}), 404

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, path FROM files WHERE id = ?', (share['file_id'],))
    file_info = cursor.fetchone()
    conn.close()

    if not file_info:
        record_audit(
            ACTION_SHARE_DOWNLOAD, RESULT_FAILURE,
            object_type='share_link', object_id=share_id,
            object_name=share['filename'],
            detail={'reason': 'file_not_found'}
        )
        return jsonify({'error': '文件不存在'}), 404

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        record_audit(
            ACTION_SHARE_DOWNLOAD, RESULT_FAILURE,
            object_type='share_link', object_id=share_id,
            object_name=file_info['name'],
            detail={'reason': 'invalid_path'}
        )
        return jsonify({'error': '非法文件路径'}), 403

    if not os.path.exists(file_info['path']):
        record_audit(
            ACTION_SHARE_DOWNLOAD, RESULT_FAILURE,
            object_type='share_link', object_id=share_id,
            object_name=file_info['name'],
            detail={'reason': 'file_missing_on_disk'}
        )
        return jsonify({'error': '文件不存在'}), 404

    increment_download_count(share_id)

    record_audit(
        ACTION_SHARE_DOWNLOAD, RESULT_SUCCESS,
        actor=None, actor_type='guest',
        object_type='share_link', object_id=share_id, object_name=file_info['name'],
        detail={'channel': 'share_link',
                'file_id': share['file_id'],
                'share_owner': share['created_by']}
    )

    logger.info(f"分享下载: 文件 {file_info['name']}, 分享ID {share_id}, 下载次数 {share['download_count'] + 1}")
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
        record_audit(
            ACTION_SHARE_DELETE, RESULT_FAILURE, actor=username,
            object_type='share_link', object_id=share_id,
            detail={'reason': 'share_not_found'}
        )
        return jsonify({'error': '分享链接不存在'}), 404

    if share['created_by'] != username:
        conn.close()
        record_audit(
            ACTION_SHARE_DELETE, RESULT_FAILURE, actor=username,
            object_type='share_link', object_id=share_id,
            detail={'reason': 'forbidden', 'owner': share['created_by']}
        )
        return jsonify({'error': '无权限删除此分享链接'}), 403

    file_id = share['file_id']
    cursor.execute('SELECT name FROM files WHERE id = ?', (file_id,))
    file_row = cursor.fetchone()
    file_name = file_row['name'] if file_row else None

    cursor.execute('DELETE FROM share_links WHERE id = ?', (share_id,))
    # 删除动作与对象信息同事务留痕
    record_audit(
        ACTION_SHARE_DELETE, RESULT_SUCCESS, actor=username,
        object_type='share_link', object_id=share_id, object_name=file_name,
        detail={'file_id': file_id}, conn=conn, commit=False
    )
    conn.commit()
    conn.close()

    logger.info(f"分享链接删除: 分享ID {share_id}, 文件ID {file_id}, 操作者 {username}")
    return jsonify({'success': True, 'message': '分享链接已删除'})
