from flask import Flask

from config import Config
from extensions import db, migrate
from routes.general import general
from routes.frontend import frontend


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
    app.register_blueprint(frontend)
    return None


def register_commands(app: Flask):
    """
    Register click commands from the commands module. Register only groups.
    """
    from commands.images import images
    app.cli.add_command(images)
    from commands.hosts import hosts
    app.cli.add_command(hosts)
    from commands.containers import containers
    app.cli.add_command(containers)


if __name__ == '__main__':
    create_app = create_app()
    create_app.run(host="127.0.0.1", port=8000)
