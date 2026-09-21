"""审计路由：审计记录查询与导出"""
import csv
import io
import json
import logging
from datetime import datetime, timezone

from flask import request, jsonify, Response

from routes import audit_bp
from auth import login_required, get_username_from_token
from audit import (
    ACTION_LABELS, VALID_ACTIONS, ACTION_EXPORT, extract_token,
    query_audit_logs, get_audit_logs_by_ids, record_audit,
)

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    ('id', '记录ID'),
    ('created_at', '时间'),
    ('action_label', '动作'),
    ('result_label', '结果'),
    ('operator', '操作者'),
    ('object_type_label', '对象类型'),
    ('object_id', '对象ID'),
    ('object_name', '对象名称'),
    ('reason', '结果说明'),
    ('ip', 'IP地址'),
    ('detail_text', '详情'),
]

OBJECT_TYPE_LABELS = {
    'file': '文件',
    'share_link': '分享链接',
    'audit_log': '审计记录',
    'auth': '身份凭据',
}


def _parse_export_ids(raw):
    """解析导出请求中的记录 ID，返回 (ids, error)"""
    if isinstance(raw, int):
        raw = [raw]
    if not isinstance(raw, list):
        return None, '缺少待导出的审计记录'
    ids = []
    seen = set()
    for value in raw:
        try:
            rid = int(value)
        except (TypeError, ValueError):
            continue
        if rid > 0 and rid not in seen:
            seen.add(rid)
            ids.append(rid)
    if not ids:
        return None, '请至少选择一条审计记录后再导出'
    return ids, None


def _record_export(operator, result, ids=None, reason=None, count=0, fmt=None):
    record_audit(
        ACTION_EXPORT, result, operator=operator,
        object_type='audit_log',
        object_name=f'审计导出（{len(ids) if ids else 0} 条）',
        detail={'record_ids': ids or [], 'format': fmt, 'count': count},
        reason=reason,
    )


@audit_bp.route('/api/audit-logs', methods=['GET'])
@login_required
def list_audit_logs():
    """分页查询审计记录（固定时间倒序、ID 倒序，保证顺序与总数稳定）"""
    action = request.args.get('action', '').strip() or None
    result = request.args.get('result', '').strip() or None
    keyword = request.args.get('keyword', '').strip() or None

    if action and action not in VALID_ACTIONS:
        return jsonify({'error': '未知的动作类型筛选'}), 400
    if result and result not in ('success', 'fail'):
        return jsonify({'error': '未知的结果类型筛选'}), 400

    items, total, page, page_size = query_audit_logs(
        action=action, result=result, keyword=keyword,
        page=request.args.get('page', 1),
        page_size=request.args.get('page_size', 20),
    )

    return jsonify({
        'items': items,
        'total': total,
        'page': page,
        'page_size': page_size,
        'action_labels': ACTION_LABELS,
    })


@audit_bp.route('/api/audit/export', methods=['POST'])
@login_required
def export_audit_logs():
    """把所选审计记录导出为可下载的审计文件（CSV / JSON）"""
    operator = get_username_from_token(extract_token())

    data = request.get_json(silent=True)
    if not data:
        _record_export(operator, 'fail', reason='无效的请求数据')
        return jsonify({'error': '无效的请求数据'}), 400

    fmt = (data.get('format') or 'csv').lower()
    if fmt not in ('csv', 'json'):
        _record_export(operator, 'fail', reason='不支持的导出格式', fmt=fmt)
        return jsonify({'error': '不支持的导出格式，仅支持 csv 或 json'}), 400

    ids, error = _parse_export_ids(data.get('ids'))
    if error:
        # 选择为空时不清除前端选择，仅说明原因
        _record_export(operator, 'fail', reason=error, fmt=fmt)
        return jsonify({'error': error}), 400

    try:
        records = get_audit_logs_by_ids(ids)
        missing = sorted(set(ids) - {r['id'] for r in records})
        if missing:
            reason = f'所选记录中有 {len(missing)} 条已不存在，选择未改动，请重新勾选'
            _record_export(operator, 'fail', ids=ids, reason=reason, fmt=fmt)
            return jsonify({'error': reason, 'missing_ids': missing}), 409

        exported_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        filename_ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')

        if fmt == 'json':
            payload = {
                'exported_at': exported_at,
                'exported_by': operator,
                'count': len(records),
                'records': records,
            }
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')
            mimetype = 'application/json'
            download_name = f'audit-logs-{filename_ts}.json'
        else:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow([label for _, label in CSV_COLUMNS])
            for record in records:
                detail = record.get('detail')
                if isinstance(detail, (dict, list)):
                    detail_text = json.dumps(detail, ensure_ascii=False)
                else:
                    detail_text = detail or ''
                row_map = {
                    **record,
                    'action_label': ACTION_LABELS.get(record.get('action'), record.get('action')),
                    'result_label': '成功' if record.get('result') == 'success' else '失败',
                    'object_type_label': OBJECT_TYPE_LABELS.get(
                        record.get('object_type'), record.get('object_type') or ''),
                    'detail_text': detail_text,
                }
                writer.writerow([row_map.get(key, '') or '' for key, _ in CSV_COLUMNS])
            # BOM 便于 Excel 正确识别 UTF-8 中文
            body = '\ufeff'.encode('utf-8') + buffer.getvalue().encode('utf-8')
            mimetype = 'text/csv'
            download_name = f'audit-logs-{filename_ts}.csv'

        _record_export(operator, 'success', ids=ids, count=len(records), fmt=fmt)

        response = Response(body, mimetype=mimetype)
        response.headers['Content-Disposition'] = (
            f"attachment; filename={download_name}; "
            f"filename*=UTF-8''{download_name}"
        )
        return response

    except Exception:
        logger.exception('生成审计文件失败')
        _record_export(operator, 'fail', ids=ids, reason='审计文件生成失败，请稍后重试', fmt=fmt)
        return jsonify({'error': '审计文件生成失败，请稍后重试，当前选择已保留'}), 500
