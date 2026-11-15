"""离线核验证据包（自包含：仅标准库 + cryptography，可单文件拷贝到离线机器）。

用法：
    python -m scripts.verify_package 证据包.json [--checkpoint 上次凭证.json]
                [--pubkey 公钥.pem] [--emit-checkpoint 新凭证输出.json]

核验能力：
- 改写：逐节重算事件哈希与链节前驱衔接；
- 丢失记录：序号必须连续且数量与包声明一致；
- 截尾：最后一节必须落在包声明的截止点与链头哈希上；
- 续验：非首包必须提供独立保管的上次凭证，凭证签名有效且与包间链衔接。
退出码 0 = 通过；1 = 失败（原因打印到 stderr）。
"""
import argparse
import base64
import hashlib
import json
import os
import sys

ZERO_HASH = '0' * 64
FORMAT_VERSION = 1


# --- 与 src/services/ledger_core.py 保持一致的哈希口径（同步由测试断言） ---
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def sha256_hex(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def event_digest(prev_hash, seq, event_type, entity_kind, entity_id, payload, created_at_ms):
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
    return sha256_hex(canonical(package_body))


class VerificationError(Exception):
    pass


def _load_json(path, what):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise VerificationError(f'{what}无法读取或不是合法 JSON（文件可能被截尾）：{e}')


def _verify_signature(pubkey, signature_b64, signed_hex):
    from cryptography.exceptions import InvalidSignature
    try:
        pubkey.verify(base64.b64decode(signature_b64), signed_hex.encode('ascii'))
    except InvalidSignature:
        raise VerificationError('签名无效：文件被改写或非本系统签发')


def _load_pubkey(path):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        with open(path, 'rb') as f:
            return load_pem_public_key(f.read())
    except Exception as e:
        raise VerificationError(f'公钥无法加载：{e}')


def verify_package(package_path, checkpoint_path=None, pubkey_path=None):
    """核验一个证据包，返回新凭证 dict（供独立保管、下次续验）。"""
    pkg = _load_json(package_path, '证据包')
    if pkg.get('kind') != 'evidence-package' or pkg.get('v') != FORMAT_VERSION:
        raise VerificationError('不是本格式的证据包')
    if pubkey_path is None:
        pubkey_path = os.path.join(os.path.dirname(os.path.abspath(package_path)), 'evidence-pubkey.pem')
    pubkey = _load_pubkey(pubkey_path)

    signature = pkg.get('signature')
    body = {k: pkg[k] for k in pkg if k != 'signature'}
    package_hash = package_digest(body)
    _verify_signature(pubkey, signature, package_hash)

    events = pkg.get('events') or []
    if len(events) != pkg.get('event_count'):
        raise VerificationError(f"包内记录数 {len(events)} 与声明的 {pkg.get('event_count')} 不符，存在丢失记录或截尾")

    prev_hash = pkg.get('prev_package_hash')
    if prev_hash is None:
        if pkg.get('package_seq') != 1:
            raise VerificationError('缺少上一包哈希但包序号不是 1，包间链被改写')
        if not events or events[0]['seq'] != 1 or events[0]['prev'] != ZERO_HASH:
            raise VerificationError('首包未从创世事件开始，链头被改写')
    else:
        if not checkpoint_path:
            raise VerificationError('该包接续上一包，必须提供独立保管的上次凭证（--checkpoint）才能续验')
        cp = _load_json(checkpoint_path, '上次凭证')
        if cp.get('kind') != 'evidence-checkpoint' or cp.get('v') != FORMAT_VERSION:
            raise VerificationError('上次凭证不是本格式')
        _verify_signature(pubkey, cp.get('signature', ''), cp.get('package_hash', ''))
        if cp.get('package_hash') != prev_hash:
            raise VerificationError('证据包声明的上一包哈希与独立保管的上次凭证不符，存在改写或掉包')
        if cp.get('package_seq', 0) + 1 != pkg.get('package_seq'):
            raise VerificationError('包序号与上次凭证不连续，中间可能有包被抽走')
        if not events or events[0]['seq'] != cp['cutoff_seq'] + 1 or events[0]['prev'] != cp['head_hash']:
            raise VerificationError('首条记录未衔接上次凭证的截止点，存在记录丢失或改写')

    prev, expected = (ZERO_HASH, 1) if prev_hash is None else (cp['head_hash'], cp['cutoff_seq'] + 1)
    for e in events:
        if e.get('seq') != expected:
            raise VerificationError(f'序号 {expected} 缺失（实际跳到 {e.get("seq")}），存在丢失记录')
        if e.get('prev') != prev:
            raise VerificationError(f'序号 {expected} 的前驱哈希与上一节不符，链节被改写或插入')
        ent = e.get('entity') or {}
        digest = event_digest(e['prev'], e['seq'], e.get('type'), ent.get('kind', ''),
                              ent.get('id', ''), e.get('payload'), e.get('at'))
        if digest != e.get('hash'):
            raise VerificationError(f'序号 {expected} 的内容哈希校验失败，记录被改写')
        prev, expected = e['hash'], expected + 1

    if not events or events[-1]['seq'] != pkg.get('cutoff_seq') or events[-1]['hash'] != pkg.get('head_hash'):
        raise VerificationError('最后一条记录未到达包声明的截止点，包被截尾')

    return {'kind': 'evidence-checkpoint', 'v': FORMAT_VERSION,
            'package_seq': pkg['package_seq'], 'cutoff_seq': pkg['cutoff_seq'],
            'head_hash': pkg['head_hash'], 'package_hash': package_hash,
            'key_id': pkg.get('key_id'), 'signature': signature,
            'exported_at_ms': pkg.get('exported_at_ms')}


def main(argv=None):
    p = argparse.ArgumentParser(description='离线核验证据包')
    p.add_argument('package', help='证据包 JSON 路径')
    p.add_argument('--checkpoint', help='独立保管的上次凭证 JSON（非首包必填）')
    p.add_argument('--pubkey', help='公钥 PEM（默认取证据包同目录 evidence-pubkey.pem）')
    p.add_argument('--emit-checkpoint', help='核验通过后将新凭证写入该路径，供下次续验')
    args = p.parse_args(argv)
    try:
        checkpoint = verify_package(args.package, args.checkpoint, args.pubkey)
    except VerificationError as e:
        print(f'核验失败：{e}', file=sys.stderr)
        return 1
    if args.emit_checkpoint:
        with open(args.emit_checkpoint, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, ensure_ascii=False, indent=1)
    print(json.dumps({'result': 'ok', 'package_seq': checkpoint['package_seq'],
                      'cutoff_seq': checkpoint['cutoff_seq'],
                      'head_hash': checkpoint['head_hash'],
                      'message': '核验通过；请将输出的新凭证独立保管，供下次续验'},
                     ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
