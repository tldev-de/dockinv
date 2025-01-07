from flask import Flask

from dockinv_server.config import Config
from dockinv_server.extensions import db, migrate
from dockinv_server.routes.general import general


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    register_blueprints(app)
    register_extensions(app)
    register_commands(app)
    return app


def register_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)
    return None


def register_blueprints(app):
    app.register_blueprint(general)
    return None


def register_commands(app: Flask):
    """
    Register click commands from the commands module. Register only groups.
    """
    from dockinv_server.commands.images import images
    app.cli.add_command(images)
    from dockinv_server.commands.hosts import hosts
    app.cli.add_command(hosts)
    from dockinv_server.commands.containers import containers
    app.cli.add_command(containers)
