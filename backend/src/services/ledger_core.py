"""证据链哈希口径（纯标准库）。

本模块是在线记账 (ledger.py) 与离线核验 (scripts/verify_package.py) 共用的
唯一哈希口径来源：任何字段的序列化方式改动都会使既有证据无法续验，
因此必须保持稳定。verify_package.py 内联了同样的实现以便单文件离线分发，
tests/test_export_verify.py 会断言两者输出一致。
"""
import hashlib
import json
import time

ZERO_HASH = '0' * 64  # 创世事件的前驱哈希
FORMAT_VERSION = 1


def canonical(obj):
    """确定性 JSON：键排序、无空白、非 ASCII 不转义、拒绝 NaN/Inf。"""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def sha256_hex(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def now_ms():
    return int(time.time() * 1000)


def event_digest(prev_hash, seq, event_type, entity_kind, entity_id, payload, created_at_ms):
    """单条证据事件的哈希。payload 为已解析的对象（非字符串）。"""
    body = {
        'v': FORMAT_VERSION,
        'seq': int(seq),
        'prev': str(prev_hash),
        'type': str(event_type),
        'entity': {'kind': str(entity_kind), 'id': str(entity_id)},
        'payload': payload,
        'at': int(created_at_ms),
    }
    return sha256_hex(canonical(body))


def package_digest(package_body):
    """证据包（不含 signature 字段）的哈希，即被签名的内容。"""
    return sha256_hex(canonical(package_body))
