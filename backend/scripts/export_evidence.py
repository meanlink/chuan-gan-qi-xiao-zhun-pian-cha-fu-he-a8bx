"""运维导出：从数据库导出证据包与凭证。

用法（backend/ 目录下）：
    python -m scripts.export_evidence [导出目录]
"""
import json
import sys
from fastapi import HTTPException
from src.config.database import Session
from src.config.settings import LEDGER_EXPORT_DIR
from src.services.ledger_export import export_package


def main(argv=None):
    out_dir = (argv or sys.argv[1:] or [LEDGER_EXPORT_DIR])[0]
    with Session() as db:
        try:
            summary = export_package(db, export_dir=out_dir)
        except HTTPException as e:
            print(f'导出未执行：{e.detail}', file=sys.stderr)
            return 1
        db.commit()
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
