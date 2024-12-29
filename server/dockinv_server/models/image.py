from dataclasses import dataclass

from dockinv_server.extensions import db
from datetime import datetime, timezone

from dockinv_server.models.base_model import BaseModel


@dataclass
class Image(db.Model, BaseModel):
    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(254), nullable=False)
    repo_digest: str = db.Column(db.String(254), nullable=True, unique=True)
    status_xeol: str = db.Column(db.JSON, nullable=True)
    status_trivy: str = db.Column(db.JSON, nullable=True)
    created_at: datetime = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at: datetime = db.Column(db.DateTime, nullable=True, onupdate=datetime.now(timezone.utc))