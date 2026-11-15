"""多进程并发追加：链不分叉、序号连续、全部落账。"""
import multiprocessing as mp
import os

from sqlalchemy import select, func

from src.models import EvidenceEvent, ChainHead
from src.services import ledger


def _append_worker(db_url, count, label):
    # spawn 子进程：重新导入本模块，各自持有独立引擎与连接
    os.environ['DATABASE_URL'] = db_url
    from src.config.database import Session
    from src.services import ledger as lg
    for i in range(count):
        with Session() as db:
            lg.record(db, 'test.ping', 'test', label, {'i': i, 'worker': label})
            db.commit()


def test_concurrent_appends_do_not_fork(db, tmp_path):
    db_url = os.environ['DATABASE_URL']
    procs, per_proc = 6, 20
    ctx = mp.get_context('spawn')
    workers = [ctx.Process(target=_append_worker, args=(db_url, per_proc, f'w{i}')) for i in range(procs)]
    for p in workers:
        p.start()
    for p in workers:
        p.join(120)
    assert all(p.exitcode == 0 for p in workers), [p.exitcode for p in workers]

    total = procs * per_proc
    head = db.get(ChainHead, 1)
    assert head.head_seq == 1 + total  # 创世 + 全部追加，无丢失
    seqs = [s for (s,) in db.execute(select(EvidenceEvent.seq).order_by(EvidenceEvent.seq))]
    assert seqs == list(range(1, total + 2))  # 连续无分叉
    assert db.scalar(select(func.count()).select_from(EvidenceEvent)) == total + 1
    assert ledger.verify_chain(db)['ok']
