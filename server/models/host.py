from dataclasses import dataclass

from extensions import db
from datetime import datetime, timezone

from models.base_model import BaseModel


@dataclass
class Host(db.Model, BaseModel):
    id: int = db.Column(db.Integer, primary_key=True)
    enabled: bool = db.Column(db.Boolean, nullable=False, default=True)
    name: str = db.Column(db.String(254), nullable=False, unique=True)
    address: str = db.Column(db.String(80), nullable=False, unique=True)
    token: str = db.Column(db.String(254), nullable=False)
    created_at: datetime = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at: datetime = db.Column(db.DateTime, nullable=True, onupdate=datetime.now(timezone.utc))