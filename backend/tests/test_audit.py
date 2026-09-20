"""传输审计模块测试"""
import io
import json
import csv

from auth import rate_limit_store
from audit import query_audit_logs, ACTION_UPLOAD, ACTION_DOWNLOAD, ACTION_AUTH


def _login(client, username='admin', password='admin123'):
    rate_limit_store.clear()
    resp = client.post('/api/auth', json={'username': username, 'password': password})
    return resp.get_json()['token']


def _auth_headers(token):
    return {'Authorization': f'Bearer {token}'}


def _upload(client, name='audit-test.txt', content=b'audit content'):
    data = {'file': (io.BytesIO(content), name)}
    resp = client.post('/api/upload', data=data, content_type='multipart/form-data')
    return resp.get_json()


def test_auth_action_audited(client):
    """登录成功与失败都应留下授权审计记录"""
    rate_limit_store.clear()
    client.post('/api/auth', json={'username': 'admin', 'password': 'admin123'})
    rate_limit_store.clear()
    client.post('/api/auth', json={'username': 'admin', 'password': 'badpass'})

    logs, total = query_audit_logs(action=ACTION_AUTH, limit=10)
    assert total == 2
    results = {row['result'] for row in logs}
    assert results == {'success', 'failure'}
    # 最新一条是失败记录（顺序稳定：id 倒序）
    assert logs[0]['result'] == 'failure'
    assert logs[0]['actor'] == 'admin'


def test_upload_action_audited(client):
    """文件接收成功要归档，且操作者信息与文件信息在同一条记录"""
    result = _upload(client)
    logs, total = query_audit_logs(action=ACTION_UPLOAD, result='success')
    assert total == 1
    log = logs[0]
    assert log['object_id'] == result['file_id']
    assert log['object_name'] == 'audit-test.txt'
    assert log['result'] == 'success'


def test_blocked_upload_audited_as_failure(client):
    """被拒绝的接收也要留痕为失败"""
    data = {'file': (io.BytesIO(b'x'), 'evil.exe')}
    resp = client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert resp.status_code == 400
    logs, total = query_audit_logs(action=ACTION_UPLOAD, result='failure')
    assert total == 1
    assert logs[0]['object_name'] == 'evil.exe'


def test_download_audited_with_identity(client):
    """取件记录的操作者与文件信息必须对得上"""
    token = _login(client)
    uploaded = _upload(client, name='dl-audit.txt')

    resp = client.get(f"/api/download/{uploaded['file_id']}",
                      headers=_auth_headers(token))
    assert resp.status_code == 200

    logs, _ = query_audit_logs(action=ACTION_DOWNLOAD, result='success')
    assert len(logs) == 1
    log = logs[0]
    assert log['actor'] == 'admin'
    assert log['object_id'] == uploaded['file_id']
    assert log['object_name'] == 'dl-audit.txt'


def test_download_failure_audited(client):
    """未授权取件 / 文件不存在都要记录失败原因"""
    token = _login(client)

    client.get('/api/download/whatever')
    resp = client.get('/api/download/missing-id', headers=_auth_headers(token))
    assert resp.status_code == 404

    logs, total = query_audit_logs(action=ACTION_DOWNLOAD, result='failure')
    assert total == 2
    reasons = {json.loads(row['detail'])['reason'] for row in logs}
    assert 'unauthorized' in reasons
    assert 'file_not_found' in reasons


def test_share_lifecycle_audited(client):
    """创建、取件、删除分享的完整链路均应留痕"""
    token = _login(client)
    uploaded = _upload(client, name='share-audit.txt')

    create_resp = client.post('/api/share', json={'file_id': uploaded['file_id']},
                              headers=_auth_headers(token))
    share_id = create_resp.get_json()['share_id']

    dl_resp = client.get(f'/api/share/{share_id}/download')
    assert dl_resp.status_code == 200

    del_resp = client.delete(f'/api/share/{share_id}', headers=_auth_headers(token))
    assert del_resp.status_code == 200

    create_logs, _ = query_audit_logs(action='share_create', result='success')
    sd_logs, _ = query_audit_logs(action='share_download', result='success')
    del_logs, _ = query_audit_logs(action='share_delete', result='success')

    assert create_logs[0]['object_id'] == share_id
    assert create_logs[0]['actor'] == 'admin'
    assert create_logs[0]['object_name'] == 'share-audit.txt'

    assert sd_logs[0]['object_id'] == share_id
    assert sd_logs[0]['object_name'] == 'share-audit.txt'
    assert sd_logs[0]['actor_type'] == 'guest'
    assert sd_logs[0]['actor'] is None
    detail = json.loads(sd_logs[0]['detail'])
    assert detail['share_owner'] == 'admin'
    assert detail['file_id'] == uploaded['file_id']

    assert del_logs[0]['object_id'] == share_id
    assert del_logs[0]['actor'] == 'admin'


def test_audit_logs_requires_auth(client):
    """审计列表必须登录后访问"""
    resp = client.get('/api/audit/logs')
    assert resp.status_code == 401


def test_audit_logs_pagination_and_total(client):
    """总数与历史顺序在分页下保持稳定"""
    token = _login(client)
    # 制造 5 条上传记录（用唯一关键词隔离其他用例的数据）
    for i in range(5):
        _upload(client, name=f'pageuniq-{i}.txt', content=f'c{i}'.encode())

    resp = client.get('/api/audit/logs?action=upload&keyword=pageuniq&page=1&page_size=2',
                      headers=_auth_headers(token))
    data = resp.get_json()
    assert data['total'] == 5
    assert len(data['items']) == 2

    resp2 = client.get('/api/audit/logs?action=upload&keyword=pageuniq&page=2&page_size=2',
                       headers=_auth_headers(token))
    page2_ids = [item['id'] for item in resp2.get_json()['items']]
    page1_ids = [item['id'] for item in data['items']]
    # 两页不重复，且严格倒序
    assert set(page1_ids).isdisjoint(page2_ids)
    assert page1_ids == sorted(page1_ids, reverse=True)
    assert page2_ids == sorted(page2_ids, reverse=True)


def test_audit_logs_filter_result(client):
    """按结果与关键词过滤"""
    token = _login(client)
    _upload(client, name='findme-report.txt')

    resp = client.get('/api/audit/logs?keyword=findme',
                      headers=_auth_headers(token))
    data = resp.get_json()
    assert data['total'] == 1
    assert data['items'][0]['object_name'] == 'findme-report.txt'
    assert data['items'][0]['action_label'] == '文件接收'
    assert data['items'][0]['result_label'] == '成功'


def test_export_csv_success(client):
    """导出所选记录为可下载 CSV，且导出动作本身被记录"""
    token = _login(client)
    _upload(client, name='export-me.txt')

    logs_resp = client.get('/api/audit/logs?action=upload',
                           headers=_auth_headers(token))
    log_id = logs_resp.get_json()['items'][0]['id']

    resp = client.post('/api/audit/export',
                       json={'ids': [log_id], 'format': 'csv'},
                       headers=_auth_headers(token))
    assert resp.status_code == 200
    assert 'text/csv' in resp.content_type
    assert 'attachment' in resp.headers['Content-Disposition']
    assert resp.headers['X-Audit-Count'] == '1'

    text = resp.data.decode('utf-8-sig')
    reader = list(csv.reader(io.StringIO(text)))
    assert reader[0][0] == '记录ID'
    assert 'export-me.txt' in text
    assert '文件接收' in text

    export_logs, total = query_audit_logs(action='audit_export', result='success')
    assert total == 1
    detail = json.loads(export_logs[0]['detail'])
    assert detail['generated_count'] == 1
    assert export_logs[0]['actor'] == 'admin'


def test_export_json_success(client):
    """JSON 导出包含完整记录数组"""
    token = _login(client)
    _upload(client)
    logs_resp = client.get('/api/audit/logs', headers=_auth_headers(token))
    ids = [item['id'] for item in logs_resp.get_json()['items']]

    resp = client.post('/api/audit/export',
                       json={'ids': ids, 'format': 'json'},
                       headers=_auth_headers(token))
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload['count'] == len(ids)
    assert payload['exported_by'] == 'admin'
    assert len(payload['records']) == len(ids)


def test_export_empty_selection_keeps_selection_contract(client):
    """空选择导出：返回明确原因 empty_selection，不生成文件"""
    token = _login(client)
    _, before = query_audit_logs(action='audit_export')
    resp = client.post('/api/audit/export',
                       json={'ids': [], 'format': 'csv'},
                       headers=_auth_headers(token))
    assert resp.status_code == 400
    body = resp.get_json()
    assert body['reason'] == 'empty_selection'

    logs_after, total_after = query_audit_logs(action='audit_export')
    assert total_after == before + 1
    assert logs_after[0]['result'] == 'failure'


def test_export_bad_format(client):
    """不支持的格式返回 unsupported_format"""
    token = _login(client)
    resp = client.post('/api/audit/export',
                       json={'ids': [1], 'format': 'pdf'},
                       headers=_auth_headers(token))
    assert resp.status_code == 400
    assert resp.get_json()['reason'] == 'unsupported_format'


def test_export_nonexistent_ids(client):
    """所选记录不存在：返回 no_matching_records 且记失败"""
    token = _login(client)
    resp = client.post('/api/audit/export',
                       json={'ids': [999999], 'format': 'csv'},
                       headers=_auth_headers(token))
    assert resp.status_code == 404
    assert resp.get_json()['reason'] == 'no_matching_records'


def test_export_invalid_ids(client):
    """非法 ID 返回 invalid_ids"""
    token = _login(client)
    resp = client.post('/api/audit/export',
                       json={'ids': ['abc'], 'format': 'csv'},
                       headers=_auth_headers(token))
    assert resp.status_code == 400
    assert resp.get_json()['reason'] == 'invalid_ids'


def test_export_requires_auth(client):
    """导出必须登录"""
    resp = client.post('/api/audit/export', json={'ids': [1]})
    assert resp.status_code == 401


def test_audit_order_and_total_stable(client):
    """多次查询之间历史顺序与总数保持稳定"""
    token = _login(client)
    for i in range(3):
        _upload(client, name=f'stableuniq-{i}.txt')

    first = client.get('/api/audit/logs?action=upload&keyword=stableuniq',
                       headers=_auth_headers(token)).get_json()
    second = client.get('/api/audit/logs?action=upload&keyword=stableuniq',
                        headers=_auth_headers(token)).get_json()
    assert first['total'] == second['total'] == 3
    assert [i['id'] for i in first['items']] == [i['id'] for i in second['items']]
