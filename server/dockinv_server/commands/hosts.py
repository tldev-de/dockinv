import click
from click_aliases import ClickAliasedGroup
from flask.cli import with_appcontext
from sqlalchemy import or_

from dockinv_server.models import Host
from dockinv_server.util import render_table, generate_random_string


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
    existing = Host.query.filter(or_(Host.name == name, Host.address == address)).first()
    if existing is not None:
        print('Host with this name or address does already exist!')
    else:
        # generate token if not provided
        if token is None:
            token = generate_random_string(32)
        # add trailing slash to address if not present
        if address[-1] != '/':
            address += '/'
        host = Host(name=name, address=address, enabled=enabled, token=token)
        host.save()
        click.echo(f'Host {name} added successfully!')


@hosts.command(aliases=['change'])
@click.argument('name')
@click.option('-a', '--address', prompt=False, default=None)
@click.option('-e', '--enabled', prompt=False, default=None)
@click.option('-t', '--token', prompt=False, default=None)
@with_appcontext
def edit(name: str, address: str, enabled: bool, token: str):
    """Edit a host with the given details."""
    existing = Host.query.filter(Host.name == name).first()
    if existing is None:
        print('Host with this address does not exist!')
    if address is not None:
        existing.address = address
    if enabled is not None:
        existing.enabled = enabled
    if token is not None:
        existing.token = token
    existing.save()


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
