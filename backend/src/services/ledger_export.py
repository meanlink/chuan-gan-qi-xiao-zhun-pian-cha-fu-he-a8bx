"""证据包导出：固定截止点快照 + Ed25519 签名凭证。

- 截止点在导出开始时确定（当前链头），导出期间新增的记录序号更大，
  自然落入下一个包，不会混入本包。
- 每个包引用上一包的哈希（prev_package_hash），凭证文件由核验方独立保管，
  下次导出/核验凭上次凭证续验，形成包间链。
- 私钥只存在于 LEDGER_KEY_DIR；公钥随包分发，离线核验不依赖本系统在线。
"""
import base64
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from src.config.settings import LEDGER_KEY_DIR, LEDGER_EXPORT_DIR
from src.models import EvidenceEvent, EvidenceCheckpoint
from src.services.ledger_core import now_ms, package_digest, sha256_hex

PUBKEY_FILE = 'evidence-pubkey.pem'


def ensure_keys(key_dir=None):
    """加载或生成签名密钥对，返回 (私钥, key_id, 公钥PEM)。私钥文件 0600。"""
    key_dir = key_dir or LEDGER_KEY_DIR
    os.makedirs(key_dir, exist_ok=True)
    priv_path = os.path.join(key_dir, 'ed25519-private.pem')
    pub_path = os.path.join(key_dir, 'ed25519-public.pem')
    if os.path.exists(priv_path):
        with open(priv_path, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    else:
        priv = Ed25519PrivateKey.generate()
        data = priv.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        with open(pub_path, 'wb') as f:
            f.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = sha256_hex(pub_pem.decode('ascii'))[:16]
    return priv, key_id, pub_pem


def export_package(db, export_dir=None, key_dir=None):
    """导出增量证据包：从上一凭证截止点之后到当前链头。

    两阶段：先在短事务内取固定截止点与事件快照并释放（写文件期间不持锁，
    导出期间新增的记录正常入链、留给下一包）；文件落盘后在第二个短事务
    登记凭证行，package_seq 唯一约束裁决并发导出。调用方负责最后提交。
    """
    from fastapi import HTTPException
    from sqlalchemy.exc import IntegrityError
    from src.models import ChainHead
    export_dir = export_dir or LEDGER_EXPORT_DIR
    os.makedirs(export_dir, exist_ok=True)
    head_row = db.execute(select(ChainHead.head_seq).where(ChainHead.id == 1)).first()
    if head_row is None:
        from src.services.ledger import ensure_genesis
        ensure_genesis(db)
        head_row = db.execute(select(ChainHead.head_seq).where(ChainHead.id == 1)).first()
    cutoff = head_row[0]  # 固定截止点：之后追加的记录留给下一包
    prev_cp = db.scalars(select(EvidenceCheckpoint).order_by(EvidenceCheckpoint.package_seq.desc())).first()
    start = prev_cp.cutoff_seq + 1 if prev_cp else 1
    events = list(db.scalars(select(EvidenceEvent)
                             .where(EvidenceEvent.seq >= start, EvidenceEvent.seq <= cutoff)
                             .order_by(EvidenceEvent.seq)))
    if not events:
        raise HTTPException(409, '自上次导出以来没有新记录，无需打包')
    snapshot = [(e.seq, e.event_type, e.entity_kind, e.entity_id, e.payload_json,
                 e.prev_hash, e.hash, e.created_at_ms) for e in events]
    package_seq = (prev_cp.package_seq + 1) if prev_cp else 1
    prev_package_hash = prev_cp.package_hash if prev_cp else None
    db.rollback()  # 释放读快照：文件落盘期间不阻塞链上追加

    priv, key_id, pub_pem = ensure_keys(key_dir)
    body = {
        'kind': 'evidence-package', 'v': 1,
        'package_seq': package_seq,
        'prev_package_hash': prev_package_hash,
        'cutoff_seq': cutoff,
        'head_hash': snapshot[-1][6],
        'event_count': len(snapshot),
        'exported_at_ms': now_ms(),
        'events': [{'seq': seq, 'type': t, 'entity': {'kind': k, 'id': i},
                    'payload': json.loads(p), 'prev': prev, 'hash': h, 'at': at}
                   for seq, t, k, i, p, prev, h, at in snapshot],
        'key_id': key_id,
    }
    package_hash = package_digest(body)
    signature = base64.b64encode(priv.sign(package_hash.encode('ascii'))).decode('ascii')
    package = {**body, 'signature': signature}
    checkpoint = {
        'kind': 'evidence-checkpoint', 'v': 1,
        'package_seq': package_seq,
        'cutoff_seq': body['cutoff_seq'],
        'head_hash': body['head_hash'],
        'package_hash': package_hash,
        'key_id': key_id,
        'signature': signature,
        'exported_at_ms': body['exported_at_ms'],
    }
    stem = f'evidence-{"%06d" % package_seq}'
    package_path = os.path.join(export_dir, stem + '-package.json')
    checkpoint_path = os.path.join(export_dir, stem + '-checkpoint.json')
    with open(package_path, 'w', encoding='utf-8') as f:
        json.dump(package, f, ensure_ascii=False, indent=1)
    with open(checkpoint_path, 'w', encoding='utf-8') as f:
        json.dump(checkpoint, f, ensure_ascii=False, indent=1)
    with open(os.path.join(export_dir, PUBKEY_FILE), 'wb') as f:
        f.write(pub_pem)
    db.add(EvidenceCheckpoint(package_seq=package_seq, cutoff_seq=body['cutoff_seq'],
                              head_hash=body['head_hash'], package_hash=package_hash,
                              signature=signature, key_id=key_id, created_at_ms=body['exported_at_ms']))
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(409, '另一个导出正在登记同一包号，请重试')
    return {'package_seq': package_seq, 'cutoff_seq': body['cutoff_seq'],
            'head_hash': body['head_hash'], 'event_count': len(snapshot),
            'package_hash': package_hash, 'key_id': key_id,
            'package_path': package_path, 'checkpoint_path': checkpoint_path,
            'note': '凭证文件须复制到独立介质保管，下次续验以其为准'}
