import logging

from extensions import db
from sqlalchemy import exc

logger = logging.getLogger(__name__)


class BaseModel:
    def save(self):
        db.session.add(self)
        try:
            db.session.commit()
            return self
        except exc.SQLAlchemyError:
            logger.exception("Failed to save %s", type(self).__name__)
            db.session.rollback()
            return None

    def delete(self):
        db.session.delete(self)
        try:
            db.session.commit()
            return self
        except exc.SQLAlchemyError:
            logger.exception("Failed to delete %s", type(self).__name__)
            db.session.rollback()
            return None
