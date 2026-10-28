"""SQLAlchemy models for persisting investigations and findings."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import String, Float, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column,
                            relationship, sessionmaker)

from shared.config import get_settings


class Base(DeclarativeBase):
    pass


class InvestigationRow(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="pending")
    risk_rating: Mapped[str] = mapped_column(String, default="INFO")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc))
    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    scanner: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    cve_id: Mapped[str] = mapped_column(String, nullable=True)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    investigation: Mapped[InvestigationRow] = relationship(back_populates="findings")


def get_engine():
    return create_engine(get_settings().sqlite_url, future=True)


def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)
