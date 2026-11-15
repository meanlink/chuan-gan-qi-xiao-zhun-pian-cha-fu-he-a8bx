from sqlalchemy import String, Integer, BigInteger, Text
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base


class EvidenceEvent(Base):
    """哈希链证据事件。seq 从 1 连续递增（1 为创世事件），不可更新、不可删除。"""
    __tablename__ = 'evidence_events'
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(40))
    entity_kind: Mapped[str] = mapped_column(String(40), default='')
    entity_id: Mapped[str] = mapped_column(String(80), default='')
    payload_json: Mapped[str] = mapped_column(Text)  # canonical JSON，业务快照
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at_ms: Mapped[int] = mapped_column(BigInteger)


class ChainHead(Base):
    """链头单行表。追加时按行锁串行化（PG: SELECT FOR UPDATE；SQLite: BEGIN IMMEDIATE）。"""
    __tablename__ = 'evidence_chain_head'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # 恒为 1
    head_seq: Mapped[int] = mapped_column(Integer)
    head_hash: Mapped[str] = mapped_column(String(64))


class EvidenceCheckpoint(Base):
    """每次导出的凭证镜像。真正的信任锚是导出目录中独立保管的凭证文件。"""
    __tablename__ = 'evidence_checkpoints'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    package_seq: Mapped[int] = mapped_column(Integer, unique=True)
    cutoff_seq: Mapped[int] = mapped_column(Integer)
    head_hash: Mapped[str] = mapped_column(String(64))
    package_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(200))
    key_id: Mapped[str] = mapped_column(String(80))
    created_at_ms: Mapped[int] = mapped_column(BigInteger)


class LegacyLog(Base):
    """迁移前的旧日志：未认证历史，永远不进证据链，不得冒充已验证证据。"""
    __tablename__ = 'legacy_logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    imported_at_ms: Mapped[int] = mapped_column(BigInteger)
    imported_by: Mapped[str] = mapped_column(String(150), default='')
    batch_hash: Mapped[str] = mapped_column(String(64))  # 登记批次指纹，仅证明“登记过”这一事实
