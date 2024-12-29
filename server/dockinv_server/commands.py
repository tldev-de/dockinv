import click
from click_aliases import ClickAliasedGroup
from flask.cli import with_appcontext, AppGroup
from dockinv_server.models.host import Host
from dockinv_server.util import render_table, generate_random_string


# Host group
@click.group(cls=ClickAliasedGroup)
def hosts():
    """Manage hosts (add, list, remove)."""
    pass


@hosts.command(aliases=['create', 'new'])
@click.argument('name')
@click.option('-a', '--address', prompt=True, default=None)
@click.option('-e', '--enabled', prompt=False, default=True)
@click.option('-t', '--token', prompt=False, default=None)
@with_appcontext
def add(name: str, address: str, enabled: bool, token: str):
    """Create a new host with the given details."""
    existing = Host.query.filter(Host.address == address).first()
    if existing is not None:
        print('Host with this address does already exist!')
    else:
        if token is None:
            token = generate_random_string(32)
        host = Host(name=name, address=address, enabled=enabled, token=token)
        host.save()


@hosts.command(aliases=['list', 'show'])
@with_appcontext
def ls():
    """List all hosts."""
    all_hosts = Host.query.all()
    click.echo(render_table(Host, all_hosts))


@hosts.command(aliases=['delete', 'remove', 'del'])
@click.argument('name')
@with_appcontext
def rm(name: str):
    """Remove a host by its name."""
    host = Host.query.filter(Host.name == name).first()
    if host is None:
        print('Host not found!')
    else:
        host.delete()
