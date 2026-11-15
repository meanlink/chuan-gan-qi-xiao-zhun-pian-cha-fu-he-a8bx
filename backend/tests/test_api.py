"""端到端：业务四阶段入链、损坏后闸门、旧日志、导出与离线核验。"""
import json

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from scripts import verify_package as vp
from src.config.database import Session
from src.services.reports import deliver
from src.models import Report

RECORDS = [
    {'sample': f'S{i}', 'band': '低温' if i < 3 else '高温',
     'reference': 10.0 + i, 'measured': 10.2 + i}
    for i in range(6)
]


def _make_dataset(client, headers, name='T-24 测试批次'):
    r = client.post('/datasets', json={'name': name, 'source': 't.csv', 'records': RECORDS}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()['id']


def _run_job(client, headers, dataset_id, name='复核任务'):
    r = client.post('/jobs', json={'name': name, 'dataset_id': dataset_id, 'params': {}}, headers=headers)
    assert r.status_code == 201, r.text
    job_id = r.json()['id']
    from src.worker import execute
    execute(job_id)
    r = client.get(f'/jobs/{job_id}', headers=headers)
    assert r.json()['status'] == 'completed', r.json()
    return job_id


def test_full_flow_chain_and_gate(client, admin_headers):
    h = admin_headers
    dataset_id = _make_dataset(client, h)
    job_id = _run_job(client, h, dataset_id)

    r = client.post(f'/jobs/{job_id}/approve', headers=h)
    assert r.status_code == 200, r.text

    r = client.post('/reports', json={'name': '每日简报', 'job_id': job_id,
                                      'destination': '复核组', 'interval_seconds': 86400,
                                      'delay_seconds': 0}, headers=h)
    assert r.status_code == 201, r.text
    with Session() as db:
        report = db.get(Report, r.json()['id'])
        delivery = deliver(db, report)
        db.commit()
    assert delivery is not None

    st = client.get('/integrity/status', headers=h).json()
    assert st['status'] == 'ok' and st['events'] == 5  # 创世+接入+完成+批准+分发
    assert st['head']['seq'] == 5 and st['drift'] == []

    events = client.get('/integrity/events', headers=h).json()
    labels = [e['label'] for e in events]
    assert labels == ['简报分发', '批准', '分析完成', '数据接入', '证据链起点']
    assert events[1]['entity'] == {'kind': 'job', 'id': str(job_id)}

    # 第二个任务待批准，用于验证损坏后的闸门
    job2 = _run_job(client, h, dataset_id, name='复核任务二')

    # 直接改库模拟篡改批准依据对应的证据
    with Session() as db:
        db.execute(text("UPDATE evidence_events SET payload_json=:p WHERE seq=3"), {'p': '{"forged":true}'})
        db.commit()

    st = client.get('/integrity/status', headers=h).json()
    assert st['status'] == 'broken'
    assert st['first_break']['seq'] == 3
    assert st['first_break']['reason'] == 'hash_mismatch'
    assert st['first_break']['entity']['kind'] == 'job'

    # 损坏后：拒绝新增批准与分发
    r = client.post(f'/jobs/{job2}/approve', headers=h)
    assert r.status_code == 409 and '证据链已损坏' in r.json()['detail']
    r = client.post('/reports', json={'name': '被拒绝的简报', 'job_id': job_id,
                                      'destination': '复核组', 'interval_seconds': 86400,
                                      'delay_seconds': 0}, headers=h)
    assert r.status_code == 409 and '证据链已损坏' in r.json()['detail']
    with Session() as db:
        report = db.get(Report, 1)
        with pytest.raises(HTTPException) as exc:
            deliver(db, report)
        assert exc.value.status_code == 409
        db.rollback()

    # 接入不受闸门限制（保留现场证据）
    r = client.post('/datasets', json={'name': '损坏后的接入批次', 'source': 't.csv',
                                       'records': RECORDS}, headers=h)
    assert r.status_code == 201, r.text


def test_legacy_and_export_api(client, admin_headers):
    h = admin_headers
    _make_dataset(client, h)

    r = client.post('/integrity/legacy',
                    json={'source': '2025手工台账.csv', 'lines': ['旧记录一', '旧记录二']}, headers=h)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body['authenticated'] is False and body['status'] == '未认证历史'

    rows = client.get('/integrity/legacy', headers=h).json()
    assert len(rows) == 2 and all(x['authenticated'] is False for x in rows)
    assert all(x['status'] == '未认证历史' for x in rows)

    st = client.get('/integrity/status', headers=h).json()
    assert st['status'] == 'ok' and st['legacy_count'] == 2

    r = client.post('/integrity/export', headers=h)
    assert r.status_code == 201, r.text
    summary = r.json()
    cp = vp.verify_package(summary['package_path'])
    assert cp['cutoff_seq'] == summary['cutoff_seq']

    exports = client.get('/integrity/exports', headers=h).json()
    assert len(exports) == 1 and exports[0]['package_seq'] == 1

    key = client.get('/integrity/public-key', headers=h).json()
    assert key['key_id'] and 'BEGIN PUBLIC KEY' in key['pem']


def test_permissions(client, admin_headers):
    from src.utils.security import token_for
    with Session() as db:
        from src.models import User
        viewer = db.query(User).filter_by(role='viewer').one()
        analyst = db.query(User).filter_by(role='analyst').one()
        vh = {'Authorization': 'Bearer ' + token_for(viewer)}
        ah = {'Authorization': 'Bearer ' + token_for(analyst)}
    # 只读角色可查看完整性状态
    assert client.get('/integrity/status', headers=vh).status_code == 200
    # 但不能导出或登记旧日志
    assert client.post('/integrity/export', headers=vh).status_code == 403
    assert client.post('/integrity/legacy', json={'source': 'x', 'lines': ['y']}, headers=ah).status_code == 403
    # 分析员不能批准
    assert client.post('/jobs/1/approve', headers=ah).status_code == 403
