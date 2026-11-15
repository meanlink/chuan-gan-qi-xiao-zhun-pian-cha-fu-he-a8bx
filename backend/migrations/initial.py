from src.config.database import Base, engine, Session
from src import models
def migrate():
    Base.metadata.create_all(engine)
    with Session() as db:
        from src.services.ledger import ensure_genesis
        ensure_genesis(db)
        db.commit()
if __name__=='__main__':migrate()
