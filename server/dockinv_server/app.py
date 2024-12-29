import inspect
import click
from flask import Flask

from dockinv_server.config import Config
from dockinv_server.extensions import db, migrate
from dockinv_server.routes.general import general
import dockinv_server.commands as commands


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    register_blueprints(app)
    register_extensions(app)
    register_commands(app, commands)
    return app


def register_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)
    return None


def register_blueprints(app):
    app.register_blueprint(general)
    return None


def register_commands(app: Flask, commands_module):
    """
    Register click commands from the commands module. Register only groups.
    """
    for name, obj in inspect.getmembers(commands_module):
        if isinstance(obj, click.Group):
            app.cli.add_command(obj)
