from dataclasses import dataclass

from extensions import db
from datetime import datetime, timezone
from models.base_model import BaseModel


@dataclass
class Container(db.Model, BaseModel):
    id: int = db.Column(db.Integer, primary_key=True)
    host_id: int = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    host = db.relationship('Host', backref=db.backref('containers', lazy=True))
    name: str = db.Column(db.String(254), nullable=False)
    image_string: str = db.Column(db.String(254), nullable=False)
    image_id: int = db.Column(db.Integer, db.ForeignKey('image.id'), nullable=False)
    image = db.relationship('Image', backref=db.backref('containers', lazy=True))
    status: str = db.Column(db.String(20), nullable=False)
    started_at: datetime = db.Column(db.DateTime, nullable=False)
    created_at: datetime = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at: datetime = db.Column(db.DateTime, nullable=True, onupdate=datetime.now(timezone.utc))
