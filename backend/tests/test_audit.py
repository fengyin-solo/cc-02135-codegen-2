"""审计留痕模块测试"""
import io
import json
import time

from auth import rate_limit_store
from audit import record_audit, query_audit_logs, get_audit_logs_by_ids


def _login(client, username, password):
    rate_limit_store.clear()
    resp = client.post('/api/auth', json={'username': username, 'password': password})
    return resp


def _auth_header(client, username='admin', password='admin123'):
    resp = _login(client, username, password)
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def _upload(client, name='audit-temp.txt', content=b'abc'):
    resp = client.post(
        '/api/upload',
        data={'file': (io.BytesIO(content), name)},
        content_type='multipart/form-data'
    )
    return resp.get_json()['file_id']


# ---------- 权限 ----------

def test_audit_list_requires_auth(client):
    """未登录不能查看审计列表"""
    assert client.get('/api/audit-logs').status_code == 401


def test_audit_export_requires_auth(client):
    """未登录不能导出审计文件"""
    resp = client.post('/api/audit/export', json={'ids': [1]})
    assert resp.status_code == 401


# ---------- 采集与归档链路 ----------

def test_login_writes_audit_with_identity(client):
    """登录成功/失败均留痕，且操作者与凭据一致"""
    _login(client, 'admin', 'admin123')
    _login(client, 'user', 'wrong-pw')

    items, total, _, _ = query_audit_logs(action='auth')
    assert total >= 2
    by_operator = {item['operator']: item['result'] for item in items}
    assert by_operator['admin'] == 'success'
    assert by_operator['user'] == 'fail'
    assert any('用户名或密码错误' in (i['reason'] or '') for i in items if i['operator'] == 'user')


def test_upload_success_and_blocked_writes_audit(client):
    """文件接收成功与被拦截都要归档"""
    _upload(client, 'ok.txt')
    client.post(
        '/api/upload',
        data={'file': (io.BytesIO(b'x'), 'bad.exe')},
        content_type='multipart/form-data'
    )
    items, total, _, _ = query_audit_logs(action='receive')
    results = {i['result'] for i in items}
    assert results == {'success', 'fail'}
    failed = next(i for i in items if i['result'] == 'fail')
    assert failed['object_name'] == 'bad.exe'
    assert '禁止上传' in failed['reason']


def test_pickup_audit_matches_identity_and_file(client):
    """取件记录的操作者与文件信息必须对得上"""
    fid = _upload(client, 'identity.txt')
    headers = _auth_header(client, 'user', 'user123')
    resp = client.get(f'/api/download/{fid}', headers=headers)
    assert resp.status_code == 200

    items, _, _, _ = query_audit_logs(action='pickup', result='success')
    assert len(items) == 1
    record = items[0]
    assert record['operator'] == 'user'
    assert record['object_id'] == fid
    assert record['object_name'] == 'identity.txt'
    assert record['object_type'] == 'file'


def test_share_grant_and_pickup_chain(client):
    """授权 -> 分享取件整条链可在审计中串起来"""
    fid = _upload(client, 'chain.txt')
    headers = _auth_header(client)
    share_id = client.post('/api/share', json={'file_id': fid}, headers=headers).get_json()['share_id']

    # 访客匿名取件
    assert client.get(f'/api/share/{share_id}/download').status_code == 200

    grants, grant_total, _, _ = query_audit_logs(action='grant', result='success')
    assert grant_total == 1
    assert grants[0]['operator'] == 'admin'
    assert grants[0]['object_id'] == share_id
    assert grants[0]['detail']['file_id'] == fid

    pickups, pickup_total, _, _ = query_audit_logs(action='share_pickup', result='success')
    assert pickup_total == 1
    assert pickups[0]['object_id'] == share_id
    assert pickups[0]['object_name'] == 'chain.txt'
    assert pickups[0]['detail']['downloader'] == 'anonymous'


def test_delete_share_and_file_audited(client):
    """删除分享链接与删除文件均留痕"""
    fid = _upload(client, 'delete-me.txt')
    headers = _auth_header(client)
    share_id = client.post('/api/share', json={'file_id': fid}, headers=headers).get_json()['share_id']
    client.delete(f'/api/share/{share_id}', headers=headers)
    client.delete(f'/api/files/{fid}', headers=headers)

    items, total, _, _ = query_audit_logs(action='delete', result='success')
    object_types = sorted(i['object_type'] for i in items)
    assert object_types == ['file', 'share_link']


def test_audit_records_survive_file_deletion(client):
    """文件删除后，历史审计记录与总数不受影响"""
    fid = _upload(client, 'persist.txt')
    headers = _auth_header(client)
    client.get(f'/api/download/{fid}', headers=headers)
    _, before_total, _, _ = query_audit_logs()

    client.delete(f'/api/files/{fid}', headers=headers)

    items, after_total, _, _ = query_audit_logs()
    assert after_total == before_total + 1  # 仅新增一条删除记录
    assert any(i['object_id'] == fid and i['action'] == 'receive' for i in items)
    assert any(i['object_id'] == fid and i['action'] == 'pickup' for i in items)


def test_unauthorized_pickup_recorded(client):
    """未授权取件要在授权失败链路留痕"""
    fid = _upload(client)
    assert client.get(f'/api/download/{fid}').status_code == 401
    items, total, _, _ = query_audit_logs(action='pickup', result='fail')
    assert total >= 1
    assert items[0]['reason'] == '未授权或token已过期'


# ---------- 列表筛选、顺序、总数 ----------

def test_filter_and_keyword(client):
    """动作/结果/关键字筛选"""
    _upload(client, 'keyword-target.txt')
    headers = _auth_header(client, 'test', 'test123')
    client.post('/api/auth', json={'username': 'test', 'password': 'test123'})

    resp = client.get('/api/audit-logs?action=receive', headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert all(i['action'] == 'receive' for i in data['items'])
    assert data['total'] == len(data['items'])

    resp = client.get('/api/audit-logs?keyword=keyword-target', headers=headers)
    items = resp.get_json()['items']
    assert items and all('keyword-target' in (i['object_name'] or '') for i in items)

    resp = client.get('/api/audit-logs?result=fail', headers=headers)
    assert all(i['result'] == 'fail' for i in resp.get_json()['items'])


def test_invalid_filter_rejected(client):
    headers = _auth_header(client)
    assert client.get('/api/audit-logs?action=hack', headers=headers).status_code == 400
    assert client.get('/api/audit-logs?result=maybe', headers=headers).status_code == 400


def test_order_and_total_stable(client):
    """连续写入后顺序固定为时间倒序+ID倒序，总数只增不减"""
    headers = _auth_header(client)
    for i in range(5):
        _upload(client, f'order-{i}.txt')

    first = client.get('/api/audit-logs?action=receive&page=1&page_size=2', headers=headers).get_json()
    ids_page1 = [i['id'] for i in first['items']]
    assert ids_page1 == sorted(ids_page1, reverse=True)
    assert first['total'] >= 5

    second = client.get('/api/audit-logs?action=receive&page=2&page_size=2', headers=headers).get_json()
    assert second['total'] == first['total']  # 总数稳定
    assert not set(ids_page1) & {i['id'] for i in second['items']}  # 分页不重叠


def test_page_out_of_range_falls_back_to_last_page(client):
    headers = _auth_header(client)
    _upload(client, 'paging.txt')
    resp = client.get('/api/audit-logs?page=999&page_size=5', headers=headers)
    data = resp.get_json()
    assert data['items']
    assert data['page'] < 999


def test_empty_result_shape(client):
    headers = _auth_header(client)
    resp = client.get('/api/audit-logs?keyword=___no_such_record___', headers=headers)
    data = resp.get_json()
    assert data['items'] == []
    assert data['total'] == 0


# ---------- 导出链路 ----------

def test_export_csv_and_json(client):
    headers = _auth_header(client)
    _upload(client, 'export.txt')
    items = client.get('/api/audit-logs?page_size=5', headers=headers).get_json()['items']
    ids = [items[0]['id'], items[1]['id']]

    resp = client.post('/api/audit/export', json={'ids': ids, 'format': 'csv'}, headers=headers)
    assert resp.status_code == 200
    assert resp.mimetype == 'text/csv'
    body = resp.data.decode('utf-8-sig')
    assert '记录ID' in body
    for rid in ids:
        assert str(rid) in body

    resp = client.post('/api/audit/export', json={'ids': ids, 'format': 'json'}, headers=headers)
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['count'] == 2
    assert payload['exported_by'] == 'admin'
    exported_ids = [r['id'] for r in payload['records']]
    assert exported_ids == sorted(ids, reverse=True)  # 与列表顺序一致


def test_export_empty_selection_explains_reason(client):
    """空选择导出要返回说明，且不影响已归档数据"""
    headers = _auth_header(client)
    _, total_before, _, _ = query_audit_logs()

    resp = client.post('/api/audit/export', json={'ids': [], 'format': 'csv'}, headers=headers)
    assert resp.status_code == 400
    assert resp.get_json()['error']

    _, total_after, _, _ = query_audit_logs()
    assert total_after == total_before + 1  # 仅新增导出失败记录


def test_export_missing_ids_conflict(client):
    """所选记录不存在时返回 409 并给出缺失 ID，前端可据此保留选择"""
    headers = _auth_header(client)
    resp = client.post('/api/audit/export', json={'ids': [999999], 'format': 'csv'}, headers=headers)
    assert resp.status_code == 409
    assert resp.get_json()['missing_ids'] == [999999]


def test_export_unsupported_format(client):
    headers = _auth_header(client)
    resp = client.post('/api/audit/export', json={'ids': [1], 'format': 'exe'}, headers=headers)
    assert resp.status_code == 400


def test_export_action_itself_audited(client):
    """导出动作本身进入审计，形成导出链路闭环"""
    headers = _auth_header(client)
    _upload(client)
    items = client.get('/api/audit-logs?page_size=5', headers=headers).get_json()['items']
    ids = [items[0]['id']]

    client.post('/api/audit/export', json={'ids': ids, 'format': 'json'}, headers=headers)
    exports, total, _, _ = query_audit_logs(action='export', result='success')
    assert total >= 1
    latest = exports[0]
    assert latest['operator'] == 'admin'
    assert latest['detail']['format'] == 'json'
    assert latest['detail']['record_ids'] == ids


def test_failed_export_keeps_selection_verifiable(client):
    """失败导出归档原因，且之前选择的记录仍可按 ID 重新取出（选择不丢失的后端保证）"""
    headers = _auth_header(client)
    fid = _upload(client, 'keep-select.txt')
    client.get(f'/api/download/{fid}', headers=headers)

    items = client.get('/api/audit-logs?page_size=20', headers=headers).get_json()['items']
    target = next(i for i in items if i['object_name'] == 'keep-select.txt' and i['action'] == 'pickup')

    # 先经历一次失败导出（混入不存在 ID）
    resp = client.post(
        '/api/audit/export',
        json={'ids': [target['id'], 888888], 'format': 'csv'},
        headers=headers
    )
    assert resp.status_code == 409

    # 原选择仍可重新成功导出，说明记录没有被改动
    again = get_audit_logs_by_ids([target['id']])
    assert len(again) == 1 and again[0]['id'] == target['id']
