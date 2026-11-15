"""连续证据账：追加、核验、完整性闸门、旧日志登记。

设计要点：
- 证据事件与业务变更共用一个数据库事务，同成同败；事务回滚则两者都不存在。
- 追加经链头单行串行化（PostgreSQL 用 SELECT ... FOR UPDATE，SQLite 用
  BEGIN IMMEDIATE，见 config/database.py），多进程并发写不会分叉；
  seq 主键与 hash 唯一约束兜底，冲突时失败关闭（不补写、不覆盖）。
- 核验从创世事件逐节重放，可发现改写、丢失记录与截尾；并与库内最近一次
  导出凭证比对，识别回滚到已导出截止点之前的尾部截断。
"""
import json
from fastapi import HTTPException
from sqlalchemy import select, update, func
from sqlalchemy.exc import IntegrityError
from src.models import EvidenceEvent, ChainHead, EvidenceCheckpoint, LegacyLog
from src.services.ledger_core import ZERO_HASH, canonical, event_digest, now_ms, sha256_hex

GENESIS_TYPE = 'ledger.genesis'

# 证据链覆盖的业务阶段：接入 → 分析完成 → 批准 → 简报分发
EVENT_LABELS = {
    GENESIS_TYPE: '证据链起点',
    'dataset.ingested': '数据接入',
    'job.completed': '分析完成',
    'job.approved': '批准',
    'report.delivered': '简报分发',
    'legacy.imported': '旧日志登记',
}


# ---------- 追加 ----------

def _genesis(db):
    at = now_ms()
    h = event_digest(ZERO_HASH, 1, GENESIS_TYPE, 'ledger', '0', {'note': '证据链起点'}, at)
    db.add(EvidenceEvent(seq=1, event_type=GENESIS_TYPE, entity_kind='ledger', entity_id='0',
                         payload_json=canonical({'note': '证据链起点'}), prev_hash=ZERO_HASH,
                         hash=h, created_at_ms=at))
    db.add(ChainHead(id=1, head_seq=1, head_hash=h))
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(409, '证据链初始化发生并发冲突，请重试')


def ensure_genesis(db):
    row = db.execute(select(ChainHead.head_seq).where(ChainHead.id == 1)).first()
    if row is None:
        _genesis(db)


def _lock_head(db):
    """读取并锁定链头。列级查询绕过 ORM 身份映射，保证读到的是库内最新值。"""
    q = select(ChainHead.head_seq, ChainHead.head_hash).where(ChainHead.id == 1)
    if db.get_bind().dialect.name != 'sqlite':
        q = q.with_for_update()  # 行锁串行化并发追加；SQLite 由 BEGIN IMMEDIATE 保证
    return db.execute(q).first()


def record(db, event_type, entity_kind, entity_id, payload):
    """在调用方的事务内追加一条证据事件。业务行须已 flush，共用同一提交。"""
    head = _lock_head(db)
    if head is None:
        _genesis(db)
        head = _lock_head(db)
    head_seq, head_hash = head
    seq = head_seq + 1
    at = now_ms()
    payload_json = canonical(payload)
    h = event_digest(head_hash, seq, event_type, entity_kind, entity_id, payload, at)
    db.add(EvidenceEvent(seq=seq, event_type=event_type, entity_kind=entity_kind,
                         entity_id=str(entity_id), payload_json=payload_json,
                         prev_hash=head_hash, hash=h, created_at_ms=at))
    db.execute(update(ChainHead).where(ChainHead.id == 1).values(head_seq=seq, head_hash=h))
    try:
        db.flush()
    except IntegrityError:
        # seq/hash 唯一约束兜底：宁可本次提交整体失败，也不让链分叉
        raise HTTPException(409, '证据链追加冲突，请重试')
    return seq, h


# ---------- 业务快照 ----------

def dataset_payload(d):
    return {'name': d.name, 'source': d.source, 'rows': len(d.records), 'checksum': d.checksum}


def job_completed_payload(j, checksum):
    return {'name': j.name, 'dataset_id': j.dataset_id,
            'params_checksum': checksum(j.params), 'result_checksum': checksum(j.result)}


def job_approved_payload(j, approver, checksum):
    return {'name': j.name, 'approved_by': approver, 'result_checksum': checksum(j.result)}


def delivery_payload(delivery, report):
    return {'report_id': report.id, 'job_id': report.job_id, 'filename': delivery.filename,
            'checksum': delivery.checksum, 'destination': delivery.destination}


# ---------- 核验 ----------

def _break(seq, reason, detail, event):
    entity = None
    if event is not None and event.entity_kind:
        entity = {'kind': event.entity_kind, 'id': event.entity_id}
    return {'ok': False,
            'first_break': {'seq': seq, 'reason': reason, 'detail': detail, 'entity': entity}}


def verify_chain(db):
    """逐节重放证据链。列级读取，不受会话缓存影响。返回 {'ok', 'first_break', 'head', 'events'}。"""
    head = db.execute(select(ChainHead.head_seq, ChainHead.head_hash)
                      .where(ChainHead.id == 1)).first()
    rows = db.execute(select(EvidenceEvent.seq, EvidenceEvent.event_type,
                             EvidenceEvent.entity_kind, EvidenceEvent.entity_id,
                             EvidenceEvent.payload_json, EvidenceEvent.prev_hash,
                             EvidenceEvent.hash, EvidenceEvent.created_at_ms)
                      .order_by(EvidenceEvent.seq)).all()

    class _Ev:  # 轻量视图，保持 _break 的取值方式
        __slots__ = ('seq', 'event_type', 'entity_kind', 'entity_id',
                     'payload_json', 'prev_hash', 'hash', 'created_at_ms')

        def __init__(self, row):
            (self.seq, self.event_type, self.entity_kind, self.entity_id,
             self.payload_json, self.prev_hash, self.hash, self.created_at_ms) = row

    events = [_Ev(r) for r in rows]
    prev, expected, last = ZERO_HASH, 1, None
    for e in events:
        if e.seq != expected:
            return {**_break(expected, 'seq_gap', f'序号 {expected} 缺失（实际跳到 {e.seq}），存在丢失记录', e),
                    'head': None, 'events': len(events)}
        if e.prev_hash != prev:
            return {**_break(e.seq, 'link_mismatch', f'序号 {e.seq} 的前驱哈希与上一节不符，链节被改写或插入', e),
                    'head': None, 'events': len(events)}
        digest = event_digest(e.prev_hash, e.seq, e.event_type, e.entity_kind, e.entity_id,
                              json.loads(e.payload_json), e.created_at_ms)
        if digest != e.hash:
            return {**_break(e.seq, 'hash_mismatch', f'序号 {e.seq} 的内容哈希校验失败，记录被改写', e),
                    'head': None, 'events': len(events)}
        prev, expected, last = e.hash, expected + 1, e
    if head is None:
        return {**_break(0, 'head_diverged', '链头不存在', None), 'head': None, 'events': len(events)}
    head_seq, head_hash = head
    if last is None or head_seq != last.seq or head_hash != last.hash:
        tail = last.seq if last else 0
        return {**_break(head_seq, 'head_diverged',
                         f'链头（序号 {head_seq}）与事件表末尾（序号 {tail}）不一致，尾部可能被截断', last),
                'head': None, 'events': len(events)}
    cp = db.execute(select(EvidenceCheckpoint.package_seq, EvidenceCheckpoint.cutoff_seq,
                           EvidenceCheckpoint.head_hash)
                    .order_by(EvidenceCheckpoint.package_seq.desc())).first()
    if cp is not None:
        if head_seq < cp.cutoff_seq:
            return {**_break(head_seq, 'truncated',
                             f'链头回退到已导出凭证的截止点 {cp.cutoff_seq} 之前，尾部被截断', None),
                    'head': None, 'events': len(events)}
        anchor_hash = db.execute(select(EvidenceEvent.hash)
                                 .where(EvidenceEvent.seq == cp.cutoff_seq)).scalar_one_or_none()
        if anchor_hash is None or anchor_hash != cp.head_hash:
            return {**_break(cp.cutoff_seq, 'checkpoint_mismatch',
                             f'已导出凭证对应的链节 {cp.cutoff_seq} 被改写或删除', None),
                    'head': None, 'events': len(events)}
    return {'ok': True, 'first_break': None,
            'head': {'seq': head_seq, 'hash': head_hash}, 'events': len(events)}


def crosscheck(db, checksum):
    """业务表当前内容与证据快照比对：发现“批准后依据被改动”的争议情形。列级读取。"""
    from src.models import Dataset, Job, Delivery
    drift = []
    rows = db.execute(select(EvidenceEvent.seq, EvidenceEvent.event_type,
                             EvidenceEvent.entity_kind, EvidenceEvent.entity_id,
                             EvidenceEvent.payload_json)
                      .where(EvidenceEvent.event_type.in_(
                          ['dataset.ingested', 'job.completed', 'job.approved', 'report.delivered']))).all()
    for seq, event_type, entity_kind, entity_id, payload_json in rows:
        try:
            entity_pk = int(entity_id)
        except (TypeError, ValueError):
            continue
        p = json.loads(payload_json)
        entity = {'kind': entity_kind, 'id': entity_id}
        if event_type == 'dataset.ingested':
            row = db.execute(select(Dataset.checksum, Dataset.records)
                             .where(Dataset.id == entity_pk)).first()
            if row is None or row[0] != p.get('checksum') or len(row[1]) != p.get('rows'):
                drift.append({'seq': seq, 'entity': entity,
                              'detail': '数据批次内容与接入时的证据快照不一致'})
        elif event_type in ('job.completed', 'job.approved'):
            row = db.execute(select(Job.result, Job.approved)
                             .where(Job.id == entity_pk)).first()
            if row is None or checksum(row[0]) != p.get('result_checksum'):
                drift.append({'seq': seq, 'entity': entity,
                              'detail': '分析结果与批准时的证据快照不一致，批准依据疑似被改动'})
            elif event_type == 'job.approved' and not row[1]:
                drift.append({'seq': seq, 'entity': entity,
                              'detail': '批准状态被撤销，与证据快照不一致'})
        elif event_type == 'report.delivered':
            current = db.execute(select(Delivery.checksum)
                                 .where(Delivery.id == entity_pk)).scalar_one_or_none()
            if current is None or current != p.get('checksum'):
                drift.append({'seq': seq, 'entity': entity,
                              'detail': '分发归档与送达时的证据快照不一致'})
    return drift


def status(db, checksum):
    v = verify_chain(db)
    last_cp = db.execute(select(EvidenceCheckpoint.package_seq, EvidenceCheckpoint.cutoff_seq,
                                EvidenceCheckpoint.package_hash, EvidenceCheckpoint.created_at_ms)
                         .order_by(EvidenceCheckpoint.package_seq.desc())).first()
    return {
        'status': 'ok' if v['ok'] else 'broken',
        'checked_at_ms': now_ms(),
        'head': v['head'],
        'events': v['events'],
        'first_break': v['first_break'],
        'drift': crosscheck(db, checksum),
        'last_export': None if last_cp is None else {
            'package_seq': last_cp.package_seq, 'cutoff_seq': last_cp.cutoff_seq,
            'package_hash': last_cp.package_hash, 'created_at_ms': last_cp.created_at_ms},
        'legacy_count': db.scalar(select(func.count()).select_from(LegacyLog)),
    }


def require_intact(db):
    """完整性闸门：证据链损坏时拒绝新增批准与分发。"""
    v = verify_chain(db)
    if not v['ok']:
        b = v['first_break']
        raise HTTPException(409, f"证据链已损坏（{b['detail']}），已拒绝本次操作；请先在证据链页面核验并处理断点")


# ---------- 旧日志（未认证历史） ----------

def import_legacy(db, source, lines, actor):
    """登记迁移前旧日志。登记行为进证据链；旧日志内容本身永不认证。"""
    lines = [str(x) for x in lines if str(x).strip()]
    if not lines:
        raise HTTPException(422, '旧日志内容为空')
    batch_hash = sha256_hex(canonical([source, lines]))
    at = now_ms()
    for line in lines:
        db.add(LegacyLog(source=source, content=line, imported_at_ms=at,
                         imported_by=actor, batch_hash=batch_hash))
    record(db, 'legacy.imported', 'legacy', batch_hash[:16],
           {'source': source, 'count': len(lines), 'content_hash': batch_hash})
    return batch_hash, len(lines)
