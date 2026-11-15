import os
import sys
import tempfile
import pathlib

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

TMP = tempfile.mkdtemp(prefix='ledger-test-')
os.environ['DATABASE_URL'] = f'sqlite:///{TMP}/test.db'
os.environ['ARTIFACT_DIR'] = f'{TMP}/artifacts'
os.environ['LEDGER_KEY_DIR'] = f'{TMP}/keys'
os.environ['LEDGER_EXPORT_DIR'] = f'{TMP}/exports'
os.environ['SEED_DEMO'] = 'false'
os.environ['JWT_SECRET'] = 'ledger-test-secret'
os.environ['REDIS_URL'] = 'redis://127.0.0.1:1/0'  # 立即连接拒绝，避免测试等待

import pytest


@pytest.fixture()
def db():
    from src.config.database import Base, engine, Session
    import src.models  # noqa: F401 确保全部表已注册
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    from src.services.ledger import ensure_genesis
    with Session() as s:
        ensure_genesis(s)
        s.commit()
    with Session() as session:
        yield session
        session.rollback()


@pytest.fixture()
def users(db):
    from src.models import User
    from src.utils.security import hash_password
    created = {}
    for role in ('admin', 'analyst', 'viewer'):
        u = User(email=f'{role}@demo.local', name=role, role=role,
                 password=hash_password('Demo123!'))
        db.add(u)
        created[role] = u
    db.commit()
    return created


@pytest.fixture()
def client(users):
    from fastapi.testclient import TestClient
    from src.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_headers(client):
    r = client.post('/auth/login', json={'email': 'admin@demo.local', 'password': 'Demo123!'})
    assert r.status_code == 200, r.text
    return {'Authorization': 'Bearer ' + r.json()['access_token']}
