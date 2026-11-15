"""证据链本体：追加、核验、篡改发现、回滚原子性、闸门、旧日志。"""
import json
import pytest
from sqlalchemy import text
from fastapi import HTTPException

from src.models import EvidenceEvent, ChainHead, LegacyLog, Dataset
from src.services import ledger
from src.services.ledger_core import ZERO_HASH
from src.utils.serialization import checksum


def _append(db, n=3):
    for i in range(n):
        ledger.record(db, 'dataset.ingested', 'dataset', str(100 + i),
                      {'name': f'批次{i}', 'rows': 5 + i, 'checksum': checksum({'i': i})})
    db.commit()


def test_append_and_verify_ok(db):
    _append(db, 4)
    v = ledger.verify_chain(db)
    assert v['ok'] and v['first_break'] is None
    assert v['events'] == 5  # 创世 + 4
    assert v['head']['seq'] == 5
    genesis = db.get(EvidenceEvent, 1)
    assert genesis.prev_hash == ZERO_HASH and genesis.event_type == 'ledger.genesis'


def test_tamper_payload_detected(db):
    _append(db, 4)
    db.execute(text("UPDATE evidence_events SET payload_json=:p WHERE seq=3"), {'p': '{"rows":999}'})
    db.commit()
    v = ledger.verify_chain(db)
    assert not v['ok']
    assert v['first_break']['seq'] == 3
    assert v['first_break']['reason'] == 'hash_mismatch'
    assert v['first_break']['entity'] == {'kind': 'dataset', 'id': '101'}  # 创世占 seq1，seq3 是第二次追加


def test_tamper_link_detected(db):
    _append(db, 4)
    db.execute(text("UPDATE evidence_events SET prev_hash='abc' WHERE seq=4"))
    db.commit()
    v = ledger.verify_chain(db)
    assert not v['ok'] and v['first_break']['seq'] == 4
    assert v['first_break']['reason'] == 'link_mismatch'


def test_delete_middle_detected(db):
    _append(db, 5)
    db.execute(text('DELETE FROM evidence_events WHERE seq=3'))
    db.commit()
    v = ledger.verify_chain(db)
    assert not v['ok']
    assert v['first_break']['seq'] == 3 and v['first_break']['reason'] == 'seq_gap'


def test_truncate_tail_detected(db):
    _append(db, 5)
    db.execute(text('DELETE FROM evidence_events WHERE seq IN (SELECT seq FROM evidence_events ORDER BY seq DESC LIMIT 2)'))
    db.commit()
    v = ledger.verify_chain(db)
    assert not v['ok'] and v['first_break']['reason'] == 'head_diverged'


def test_truncate_tail_with_head_rewritten_detected_via_checkpoint(db):
    """截尾后把链头也改小：内部一致，但与已导出凭证矛盾。"""
    _append(db, 6)
    from src.services.ledger_export import export_package
    summary = export_package(db)
    db.commit()
    cutoff = summary['cutoff_seq']  # 7 = 创世 + 6
    db.execute(text('DELETE FROM evidence_events WHERE seq IN (SELECT seq FROM evidence_events ORDER BY seq DESC LIMIT 3)'))
    db.execute(text("UPDATE evidence_chain_head SET head_seq=4, head_hash=(SELECT hash FROM evidence_events WHERE seq=4)"))
    db.commit()
    v = ledger.verify_chain(db)
    assert not v['ok'] and v['first_break']['reason'] == 'truncated'
    assert cutoff == 7


def test_rollback_leaves_no_success_record(db):
    head_before = db.get(ChainHead, 1).head_seq
    d = Dataset(name='回滚批次', source='t.json', records=[{'a': 1}], checksum='x', created_at=1.0)
    db.add(d)
    db.flush()
    ledger.record(db, 'dataset.ingested', 'dataset', d.id, ledger.dataset_payload(d))
    db.rollback()  # 业务与证据同一事务：回滚后两者都不存在
    assert db.get(ChainHead, 1).head_seq == head_before
    assert db.query(Dataset).filter_by(name='回滚批次').count() == 0
    assert db.get(EvidenceEvent, head_before + 1) is None


def test_require_intact_gate(db):
    _append(db, 3)
    ledger.require_intact(db)  # 不抛异常
    db.execute(text("UPDATE evidence_events SET payload_json='{}' WHERE seq=2"))
    db.commit()
    with pytest.raises(HTTPException) as exc:
        ledger.require_intact(db)
    assert exc.value.status_code == 409
    assert '证据链已损坏' in exc.value.detail


def test_legacy_marked_unauthenticated(db):
    batch_hash, count = ledger.import_legacy(db, '旧台账.csv', ['行一', '行二'], 'tester')
    db.commit()
    rows = db.query(LegacyLog).all()
    assert count == 2 and len(rows) == 2
    # 登记行为入链，旧日志内容本身不进链
    types = [t for (t,) in db.query(EvidenceEvent.event_type).all()]
    assert 'legacy.imported' in types
    assert all(e.entity_kind != 'legacy' or e.event_type == 'legacy.imported'
               for e in db.query(EvidenceEvent).all())
    st = ledger.status(db, checksum)
    assert st['legacy_count'] == 2 and st['status'] == 'ok'


def test_crosscheck_detects_approval_basis_drift(db):
    """争议场景：批准后有人直接改了业务表里的结果。"""
    d = Dataset(name='漂移批次', source='t.json', records=[{'a': 1}], checksum=checksum([{'a': 1}]), created_at=1.0)
    db.add(d)
    db.flush()
    ledger.record(db, 'dataset.ingested', 'dataset', d.id, ledger.dataset_payload(d))
    db.commit()
    assert ledger.crosscheck(db, checksum) == []
    db.execute(text("UPDATE datasets SET checksum='forged' WHERE name='漂移批次'"))
    db.commit()
    drift = ledger.crosscheck(db, checksum)
    assert len(drift) == 1 and drift[0]['entity']['kind'] == 'dataset'
    st = ledger.status(db, checksum)
    assert st['status'] == 'ok' and len(st['drift']) == 1  # 链未断，但业务表与证据快照不一致
