import click
from click_aliases import ClickAliasedGroup
from flask.cli import with_appcontext

import util
from models import Image
from util import render_table


@click.group(cls=ClickAliasedGroup)
def images():
    """Get information about used images."""
    pass


@images.command(aliases=['list', 'show'])
@with_appcontext
def ls():
    """List all images."""
    all_images = Image.query.all()
    # overwrite image colums container json
    for image in all_images:
        image.status_xeol = util.parse_xeol_to_str(image.status_xeol)
        image.status_trivy = util.parse_trivy_to_str(image.status_trivy)
    click.echo(render_table(Image, all_images))