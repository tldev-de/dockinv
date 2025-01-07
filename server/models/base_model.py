from extensions import db
from sqlalchemy import exc


class BaseModel:
    def save(self):
        db.session.add(self)
        try:
            db.session.commit()
            return self
        except exc.SQLAlchemyError as e:
            print(e)
            db.session.rollback()
            return None

    def delete(self):
        db.session.delete(self)
        try:
            db.session.commit()
            return self
        except exc.SQLAlchemyError as e:
            print(e)
            db.session.rollback()
            return None
