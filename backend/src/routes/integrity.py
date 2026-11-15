import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from src.config.database import get_db
from src.middlewares.auth import current_user, admin_only
from src.models import EvidenceEvent, EvidenceCheckpoint, LegacyLog
from src.services import ledger
from src.services.ledger_export import export_package, ensure_keys
from src.utils.serialization import checksum

router = APIRouter(prefix='/integrity')


def _event_dict(e):
    return {'seq': e.seq, 'type': e.event_type, 'label': ledger.EVENT_LABELS.get(e.event_type, e.event_type),
            'entity': {'kind': e.entity_kind, 'id': e.entity_id},
            'payload': json.loads(e.payload_json),
            'prev': e.prev_hash, 'hash': e.hash, 'at': e.created_at_ms}


@router.get('/status')
def get_status(db=Depends(get_db), u=Depends(current_user)):
    return ledger.status(db, checksum)


@router.post('/verify')
def verify_now(db=Depends(get_db), u=Depends(current_user)):
    return ledger.status(db, checksum)


@router.get('/events')
def events(limit: int = 200, db=Depends(get_db), u=Depends(current_user)):
    limit = min(max(limit, 1), 1000)
    rows = db.scalars(select(EvidenceEvent).order_by(EvidenceEvent.seq.desc()).limit(limit))
    return [_event_dict(e) for e in rows]


@router.get('/exports')
def exports(db=Depends(get_db), u=Depends(current_user)):
    rows = db.scalars(select(EvidenceCheckpoint).order_by(EvidenceCheckpoint.package_seq.desc()))
    return [{'package_seq': c.package_seq, 'cutoff_seq': c.cutoff_seq, 'head_hash': c.head_hash,
             'package_hash': c.package_hash, 'key_id': c.key_id, 'created_at_ms': c.created_at_ms} for c in rows]


@router.post('/export', status_code=201)
def export_now(db=Depends(get_db), u=Depends(admin_only)):
    summary = export_package(db)
    db.commit()
    return summary


@router.get('/public-key')
def public_key(u=Depends(current_user)):
    _, key_id, pub_pem = ensure_keys()
    return {'key_id': key_id, 'pem': pub_pem.decode('ascii'),
            'note': '离线核验命令：python -m scripts.verify_package 证据包.json --checkpoint 上次凭证.json --pubkey 公钥.pem'}


class LegacyInput(BaseModel):
    source: str = Field(min_length=2, max_length=200)
    lines: list[str] = Field(min_length=1, max_length=5000)


@router.get('/legacy')
def legacy_list(db=Depends(get_db), u=Depends(current_user)):
    rows = db.scalars(select(LegacyLog).order_by(LegacyLog.id.desc()).limit(200))
    # authenticated 恒为 False：旧日志是未认证历史，不冒充已验证证据
    return [{'id': x.id, 'source': x.source, 'content': x.content, 'imported_at_ms': x.imported_at_ms,
             'imported_by': x.imported_by, 'authenticated': False, 'status': '未认证历史'} for x in rows]


@router.post('/legacy', status_code=201)
def legacy_import(data: LegacyInput, db=Depends(get_db), u=Depends(admin_only)):
    batch_hash, count = ledger.import_legacy(db, data.source, data.lines, u.email)
    db.commit()
    return {'batch_hash': batch_hash, 'count': count, 'authenticated': False,
            'status': '未认证历史', 'note': '登记行为已入证据链；旧日志内容本身不属于已验证证据'}
