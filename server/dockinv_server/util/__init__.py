from tabulate import tabulate
from dockinv_server.extensions import db
import random
import string


def render_table(model: db.Model, obj: list) -> str:
    columns = [column.name for column in model.__table__.columns]
    table = [[getattr(attr, column) for column in columns] for attr in obj]
    return tabulate(table, columns)


def generate_random_string(length: int) -> str:
    res = ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=length))
    return res
