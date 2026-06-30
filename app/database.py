from sqlmodel import Session, SQLModel, create_engine

from app.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Columns added to existing tables after their initial release. SQLModel's
# create_all only creates missing tables, not missing columns on tables that
# already exist — this project doesn't use Alembic, so patch them by hand.
_ADDED_COLUMNS = {
    "runhistory": [("tags", "TEXT")],
}


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    _apply_column_migrations()


def _apply_column_migrations() -> None:
    with engine.connect() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            existing = {
                row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")
            }
            for name, sql_type in columns:
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
        conn.commit()


def get_session():
    with Session(engine) as session:
        yield session
