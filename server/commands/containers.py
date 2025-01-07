import click
from click_aliases import ClickAliasedGroup
from flask.cli import with_appcontext

from models import Container
from util import render_table


@click.group(cls=ClickAliasedGroup)
def containers():
    """Get information about containers."""
    pass


@containers.command(aliases=['list', 'show'])
@with_appcontext
def ls():
    """List all containers."""
    all_containers = Container.query.all()
    click.echo(render_table(Container, all_containers))
