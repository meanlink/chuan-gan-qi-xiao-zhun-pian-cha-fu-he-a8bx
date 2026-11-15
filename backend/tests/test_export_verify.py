"""导出与离线核验：固定截止点、凭证续验、改写/丢失/截尾发现。"""
import json
import os

import pytest

from scripts import verify_package as vp
from src.config.database import Session
from src.services import ledger
from src.services.ledger_core import canonical, event_digest
from src.services.ledger_export import export_package
from src.utils.serialization import checksum


def _append(db, n, tag='批次'):
    for i in range(n):
        ledger.record(db, 'dataset.ingested', 'dataset', f'{tag}-{i}',
                      {'name': f'{tag}{i}', 'rows': i + 5, 'checksum': checksum({'i': i})})
    db.commit()


def _export(db):
    summary = export_package(db)
    db.commit()
    return summary


def _load(path):
    return json.load(open(path, encoding='utf-8'))


def _save(path, pkg):
    json.dump(pkg, open(path, 'w', encoding='utf-8'), ensure_ascii=False)


def _resign(pkg):
    """用真实私钥重签（模拟结构损坏但签名有效的包，以走到结构核验）。"""
    import base64
    from src.services.ledger_core import package_digest
    from src.services.ledger_export import ensure_keys
    priv, _, _ = ensure_keys()
    body = {k: pkg[k] for k in pkg if k != 'signature'}
    pkg['signature'] = base64.b64encode(priv.sign(package_digest(body).encode('ascii'))).decode('ascii')
    return pkg


def test_hash_parity_with_offline_script():
    """离线脚本内联的哈希口径必须与在线模块一致。"""
    payload = {'name': '含中文与浮点 0.30000000000000004', 'rows': 7, 'tags': ['a', 1, None]}
    args = ('ab' * 32, 9, 'job.approved', 'job', '5', payload, 1730000000123)
    assert vp.event_digest(*args) == event_digest(*args)
    assert vp.canonical(payload) == canonical(payload)
    body = {'kind': 'evidence-package', 'v': 1, 'events': [payload]}
    assert vp.package_digest(body) == vp.sha256_hex(vp.canonical(body))


def test_export_then_offline_verify_ok(db, tmp_path):
    _append(db, 5)
    summary = _export(db)
    assert summary['cutoff_seq'] == 6 and summary['event_count'] == 6
    assert os.path.exists(summary['package_path']) and os.path.exists(summary['checkpoint_path'])
    cp = vp.verify_package(summary['package_path'])
    assert cp['package_seq'] == 1 and cp['cutoff_seq'] == 6


def test_offline_detects_tampered_event(db):
    _append(db, 4)
    summary = _export(db)
    path = summary['package_path']
    pkg = _load(path)
    pkg['events'][2]['payload']['rows'] = 999  # 改写包内记录
    _save(path, pkg)
    # 签名已失效，且攻击者没有私钥无法重签
    with pytest.raises(vp.VerificationError, match='签名无效'):
        vp.verify_package(path)


def test_offline_detects_rehashed_tamper(db, tmp_path):
    """攻击者改记录并重算链上哈希：包哈希与签名对不上。"""
    _append(db, 4)
    summary = _export(db)
    path = summary['package_path']
    pkg = json.load(open(path, encoding='utf-8'))
    pkg['events'][2]['payload']['rows'] = 999
    for i, e in enumerate(pkg['events']):  # 重算整条链
        prev = pkg['events'][i - 1]['hash'] if i else '0' * 64
        e['prev'] = prev
        e['hash'] = vp.event_digest(prev, e['seq'], e['type'], e['entity']['kind'], e['entity']['id'], e['payload'], e['at'])
    pkg['head_hash'] = pkg['events'][-1]['hash']
    json.dump(pkg, open(path, 'w', encoding='utf-8'), ensure_ascii=False)
    with pytest.raises(vp.VerificationError, match='签名无效'):
        vp.verify_package(path)


def test_offline_detects_missing_event(db, tmp_path):
    _append(db, 5)
    summary = _export(db)
    path = summary['package_path']
    pkg = _load(path)
    del pkg['events'][2]  # 抽走一条 → 数量声明不符
    _save(path, _resign(pkg))  # 重签以走到结构核验
    with pytest.raises(vp.VerificationError, match='丢失记录|截尾'):
        vp.verify_package(path)


def test_offline_detects_truncated_package(db, tmp_path):
    _append(db, 5)
    summary = _export(db)
    path = summary['package_path']
    pkg = _load(path)
    pkg['events'] = pkg['events'][:-1]
    pkg['event_count'] = len(pkg['events'])  # 连数量一起改 → 截止点对不上
    _save(path, _resign(pkg))
    with pytest.raises(vp.VerificationError, match='截尾'):
        vp.verify_package(path)


def test_second_package_resumes_from_checkpoint(db):
    """凭独立保管的上次凭证续验；导出期间新增记录留给下一包。"""
    _append(db, 3)
    s1 = _export(db)
    cp1 = vp.verify_package(s1['package_path'])
    _append(db, 4)
    s2 = _export(db)
    assert s2['package_seq'] == 2 and s2['cutoff_seq'] == 8
    pkg2 = json.load(open(s2['package_path'], encoding='utf-8'))
    assert pkg2['events'][0]['seq'] == s1['cutoff_seq'] + 1  # 上一包截止点之后才开始
    assert pkg2['prev_package_hash'] == cp1['package_hash']
    # 无凭证 → 拒绝续验
    with pytest.raises(vp.VerificationError, match='上次凭证'):
        vp.verify_package(s2['package_path'])
    # 拿证据包冒充凭证 → 拒绝
    with pytest.raises(vp.VerificationError, match='不是本格式'):
        vp.verify_package(s2['package_path'], checkpoint_path=s1['package_path'])
    # 凭证被改动（截止点不符）→ 拒绝
    forged = _load(s1['checkpoint_path'])
    forged['cutoff_seq'] = 2
    forged_path = s1['checkpoint_path'] + '.forged'
    _save(forged_path, forged)
    with pytest.raises(vp.VerificationError, match='衔接|不连续|不符'):
        vp.verify_package(s2['package_path'], checkpoint_path=forged_path)
    # 正确凭证 → 通过
    cp2 = vp.verify_package(s2['package_path'], checkpoint_path=s1['checkpoint_path'])
    assert cp2['cutoff_seq'] == 8


def test_export_cutoff_excludes_concurrent_appends(db, monkeypatch, tmp_path):
    """导出期间（快照之后）新增的记录不进本包，留给下一包。"""
    _append(db, 3)
    from src.services import ledger_export
    real_now = ledger_export.now_ms
    state = {'injected': False}

    def now_ms_with_concurrent_append():
        if not state['injected']:
            state['injected'] = True
            with Session() as other:  # 另一会话模拟并发写入
                ledger.record(other, 'dataset.ingested', 'dataset', 'concurrent',
                              {'name': '并发批次', 'rows': 1, 'checksum': 'c'})
                other.commit()
        return real_now()

    monkeypatch.setattr(ledger_export, 'now_ms', now_ms_with_concurrent_append)
    s1 = _export(db)
    monkeypatch.undo()
    pkg = json.load(open(s1['package_path'], encoding='utf-8'))
    assert all(e['entity']['id'] != 'concurrent' for e in pkg['events'])  # 并发记录未混入
    assert s1['cutoff_seq'] == 4  # 创世 + 3，导出开始时的链头
    s2 = _export(db)
    pkg2 = json.load(open(s2['package_path'], encoding='utf-8'))
    assert pkg2['events'][0]['entity']['id'] == 'concurrent'  # 留给下一包
    cp2 = vp.verify_package(s2['package_path'], checkpoint_path=s1['checkpoint_path'])
    assert cp2['cutoff_seq'] == 5


def test_cli_exit_codes(db, tmp_path, capsys):
    _append(db, 2)
    s1 = _export(db)
    out = tmp_path / 'cp.json'
    assert vp.main([s1['package_path'], '--emit-checkpoint', str(out)]) == 0
    assert out.exists()
    pkg = json.load(open(s1['package_path'], encoding='utf-8'))
    pkg['events'][1]['payload']['rows'] = -1
    bad = tmp_path / 'bad.json'
    json.dump(pkg, open(bad, 'w', encoding='utf-8'), ensure_ascii=False)
    assert vp.main([str(bad)]) == 1
