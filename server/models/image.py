from dataclasses import dataclass
from typing import Optional

from extensions import db
from datetime import datetime, timezone

from models.base_model import BaseModel


@dataclass
class Image(db.Model, BaseModel):
    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(254), nullable=False)
    repo_digest: str = db.Column(db.String(254), nullable=True, unique=True)
    status_xeol: Optional[dict] = db.Column(db.JSON, nullable=True)
    status_trivy: Optional[dict] = db.Column(db.JSON, nullable=True)
    created_at: datetime = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: datetime = db.Column(db.DateTime, nullable=True, onupdate=lambda: datetime.now(timezone.utc))