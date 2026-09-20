"""传输审计路由

- GET  /api/audit/logs    分页查询审计记录（需登录）
- POST /api/audit/export  将所选记录导出为可下载审计文件（需登录）

导出文件由后端统一生成（CSV / JSON），无论成功失败都会留下一条
audit_export 记录，覆盖“采集 -> 归档 -> 导出”完整链路。
"""
import csv
import io
import json
import time
import logging
from flask import request, jsonify, Response
from routes import audit_bp
from auth import login_required, get_username_from_token
from database import get_db
from audit import (
    query_audit_logs, get_audit_logs_by_ids, record_audit,
    ACTION_AUDIT_EXPORT, ACTION_LABELS, RESULT_SUCCESS, RESULT_FAILURE,
)

logger = logging.getLogger(__name__)

PAGE_SIZE_DEFAULT = 20
PAGE_SIZE_MAX = 100
EXPORT_IDS_LIMIT = 1000

# 导出文件列定义：顺序固定，即审计留痕的标准字段
CSV_COLUMNS = [
    ('id', '记录ID'),
    ('occurred_at', '操作时间'),
    ('action_label', '动作'),
    ('action', '动作标识'),
    ('actor', '操作者'),
    ('actor_type', '操作者类型'),
    ('actor_ip', '来源地址'),
    ('object_type', '对象类型'),
    ('object_id', '对象ID'),
    ('object_name', '对象名称'),
    ('result_label', '结果'),
    ('result', '结果标识'),
    ('detail', '详情'),
]


def _serialize(record):
    """补充展示字段，保证同一动作在身份与文件信息之间对得上。"""
    item = dict(record)
    item['action_label'] = ACTION_LABELS.get(item.get('action'), item.get('action'))
    item['result_label'] = '成功' if item.get('result') == RESULT_SUCCESS else '失败'
    return item


@audit_bp.route('/api/audit/logs', methods=['GET'])
@login_required
def list_audit_logs():
    """分页查询审计记录

    查询参数：action / actor / result / keyword / page / page_size
    返回 {items, total, page, page_size}，total 为过滤后的稳定总数。
    """
    action = (request.args.get('action') or '').strip() or None
    actor = (request.args.get('actor') or '').strip() or None
    result = (request.args.get('result') or '').strip() or None
    keyword = (request.args.get('keyword') or '').strip() or None

    try:
        page = max(1, int(request.args.get('page', 1)))
        page_size = int(request.args.get('page_size', PAGE_SIZE_DEFAULT))
    except (TypeError, ValueError):
        return jsonify({'error': '分页参数无效'}), 400

    page_size = min(max(1, page_size), PAGE_SIZE_MAX)
    offset = (page - 1) * page_size

    conn = get_db()
    rows, total = query_audit_logs(
        action=action, actor=actor, result=result, keyword=keyword,
        limit=page_size, offset=offset, conn=conn
    )
    conn.close()

    return jsonify({
        'items': [_serialize(row) for row in rows],
        'total': total,
        'page': page,
        'page_size': page_size,
    })


def _csv_injection_safe(value):
    """防止 CSV 公式注入：=、+、-、@ 开头的单元格前加单引号。"""
    text = '' if value is None else str(value)
    if text[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + text
    return text


def _build_csv(records):
    """根据所选记录生成 CSV（utf-8-sig，便于 Excel 直接打开）。"""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([label for _, label in CSV_COLUMNS])
    for raw in records:
        row_data = _serialize(raw)
        writer.writerow([
            _csv_injection_safe(row_data.get(key)) for key, _ in CSV_COLUMNS
        ])
    # 写入 BOM 让 Excel 正确识别 UTF-8
    return '\ufeff' + buffer.getvalue()


def _build_json(records, username):
    """根据所选记录生成 JSON 审计文件。"""
    payload = {
        'exported_at': time.strftime('%Y-%m-%dT%H:%M:%S%z') or time.strftime('%Y-%m-%d %H:%M:%S'),
        'exported_by': username,
        'count': len(records),
        'records': [_serialize(row) for row in records],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


@audit_bp.route('/api/audit/export', methods=['POST'])
@login_required
def export_audit_logs():
    """导出所选审计记录

    请求体：{ids: [..], format: 'csv'|'json'}
    响应：
      - 成功：文件下载流
      - 失败：JSON {error, reason}，HTTP 4xx/5xx
    无论成功失败均写入一条 audit_export 记录（含所选数量与实际生成数量）。
    """
    token = request.headers.get('Authorization', '')[7:] \
        if request.headers.get('Authorization', '').startswith('Bearer ') \
        else request.args.get('token')
    username = get_username_from_token(token)

    data = request.get_json(silent=True) or {}
    fmt = (data.get('format') or 'csv').lower()
    raw_ids = data.get('ids') or []

    if fmt not in ('csv', 'json'):
        record_audit(
            ACTION_AUDIT_EXPORT, RESULT_FAILURE, actor=username,
            object_type='audit_export', object_name=f'audit-export.{fmt}',
            detail={'reason': 'unsupported_format', 'requested_format': fmt}
        )
        return jsonify({'error': '不支持的导出格式，仅支持 csv / json',
                        'reason': 'unsupported_format'}), 400

    if not isinstance(raw_ids, list) or not raw_ids:
        # 空选择：不生成文件，保留前端当前选择
        record_audit(
            ACTION_AUDIT_EXPORT, RESULT_FAILURE, actor=username,
            object_type='audit_export', object_name=f'audit-export.{fmt}',
            detail={'reason': 'empty_selection', 'selected_count': 0}
        )
        return jsonify({'error': '未选择任何审计记录，无法生成审计文件',
                        'reason': 'empty_selection'}), 400

    if len(raw_ids) > EXPORT_IDS_LIMIT:
        record_audit(
            ACTION_AUDIT_EXPORT, RESULT_FAILURE, actor=username,
            object_type='audit_export', object_name=f'audit-export.{fmt}',
            detail={'reason': 'too_many_records',
                    'selected_count': len(raw_ids),
                    'limit': EXPORT_IDS_LIMIT}
        )
        return jsonify({'error': f'单次最多导出 {EXPORT_IDS_LIMIT} 条记录',
                        'reason': 'too_many_records'}), 400

    # 归一化 ID，过滤非法输入
    try:
        ids = [int(x) for x in raw_ids]
    except (TypeError, ValueError):
        record_audit(
            ACTION_AUDIT_EXPORT, RESULT_FAILURE, actor=username,
            object_type='audit_export', object_name=f'audit-export.{fmt}',
            detail={'reason': 'invalid_ids', 'selected_count': len(raw_ids)}
        )
        return jsonify({'error': '存在无效的记录标识',
                        'reason': 'invalid_ids'}), 400

    conn = get_db()
    records = get_audit_logs_by_ids(ids, conn=conn)

    if not records:
        conn.close()
        # 所选记录可能已不存在；明确告知原因，前端保留选择以便用户核对
        record_audit(
            ACTION_AUDIT_EXPORT, RESULT_FAILURE, actor=username,
            object_type='audit_export', object_name=f'audit-export.{fmt}',
            detail={'reason': 'no_matching_records',
                    'selected_count': len(ids), 'generated_count': 0}
        )
        return jsonify({'error': '所选记录均不存在或已不可导出，请刷新列表后重新选择',
                        'reason': 'no_matching_records'}), 404

    # 生成审计文件；生成失败时不返回半成品，并说明原因
    try:
        if fmt == 'csv':
            content = _build_csv(records)
            mimetype = 'text/csv'
        else:
            content = _build_json(records, username)
            mimetype = 'application/json'
    except Exception as exc:  # 生成阶段的任何异常都视为文件生成失败
        conn.close()
        logger.exception('审计文件生成失败')
        record_audit(
            ACTION_AUDIT_EXPORT, RESULT_FAILURE, actor=username,
            object_type='audit_export', object_name=f'audit-export.{fmt}',
            detail={'reason': 'generation_failed',
                    'error': str(exc),
                    'selected_count': len(ids), 'generated_count': 0}
        )
        return jsonify({'error': f'审计文件生成失败：{exc}',
                        'reason': 'generation_failed'}), 500

    generated_count = len(records)
    missing_count = len(set(ids)) - generated_count

    record_audit(
        ACTION_AUDIT_EXPORT, RESULT_SUCCESS, actor=username,
        object_type='audit_export', object_name=f'audit-export.{fmt}',
        detail={'format': fmt,
                'selected_count': len(ids),
                'generated_count': generated_count,
                'missing_count': missing_count},
        conn=conn
    )
    conn.close()

    timestamp = time.strftime('%Y%m%d-%H%M%S')
    filename = f'audit-trails-{timestamp}.{fmt}'

    logger.info(f"审计导出成功: 操作者 {username}, 格式 {fmt}, 条数 {generated_count}")

    return Response(
        content,
        status=200,
        mimetype=mimetype,
        headers={
            'Content-Disposition': f"attachment; filename*=UTF-8''{filename}",
            'X-Audit-Count': str(generated_count),
            'X-Audit-Missing-Count': str(missing_count),
        }
    )
