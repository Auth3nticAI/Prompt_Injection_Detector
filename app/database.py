"""SQLite persistence for an audit trail of analyzed prompts."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from sqlalchemy import Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/prompt_logs.db")

# Ensure the SQLite directory exists when a file-backed URL is used.
if DATABASE_URL.startswith("sqlite:///") and "/data/" in DATABASE_URL:
    os.makedirs("data", exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class PromptLog(Base):
    __tablename__ = "prompt_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    prompt: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    recommended_action: Mapped[str] = mapped_column(String(16))
    categories: Mapped[str] = mapped_column(Text, default="[]")  # JSON array
    created_at: Mapped[str] = mapped_column(String(32))

    def as_entry(self) -> dict:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "categories": json.loads(self.categories or "[]"),
            "created_at": self.created_at,
        }


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
