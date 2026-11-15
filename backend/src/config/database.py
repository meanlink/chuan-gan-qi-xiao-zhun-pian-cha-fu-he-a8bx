from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .settings import DATABASE_URL

class Base(DeclarativeBase):
    pass

connect_args = {'check_same_thread': False, 'timeout': 30} if DATABASE_URL.startswith('sqlite') else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=1800, connect_args=connect_args)

if engine.dialect.name == 'sqlite':
    @event.listens_for(engine, 'connect')
    def _sqlite_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute('PRAGMA journal_mode=WAL')
        cur.execute('PRAGMA busy_timeout=30000')
        cur.execute('PRAGMA foreign_keys=ON')
        cur.close()

    @event.listens_for(engine, 'begin')
    def _sqlite_begin(conn):
        # 事务一开始即取写锁：多进程追加证据时串行排队，链头不会分叉。
        conn.exec_driver_sql('BEGIN IMMEDIATE')

Session = sessionmaker(engine, expire_on_commit=False)

def get_db():
    with Session() as db:
        yield db
