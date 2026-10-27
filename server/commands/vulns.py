import click
from click_aliases import ClickAliasedGroup
from flask.cli import with_appcontext
from sqlalchemy import func
from tabulate import tabulate

from extensions import db
from models import Vulnerability
from vulnerabilities import rebuild_all, find_drift


@click.group(cls=ClickAliasedGroup)
def vulns():
    """Manage the normalized vulnerability index (projection of status_trivy)."""
    pass


@vulns.command()
@with_appcontext
def rebuild():
    """Rebuild the vulnerability table from each image's Trivy JSON (backfill/repair)."""
    count = rebuild_all()
    click.echo(f'Rebuilt vulnerabilities for {count} image(s); '
               f'{Vulnerability.query.count()} rows total.')


@vulns.command()
@with_appcontext
def verify():
    """Check the table is in sync with status_trivy; exit non-zero on drift."""
    drifted = find_drift()
    if drifted:
        click.echo(f'DRIFT detected for {len(drifted)} image(s): {drifted}')
        click.echo("Run 'flask vulns rebuild' to repair.")
        raise SystemExit(1)
    click.echo('OK - vulnerability table is in sync with status_trivy.')


@vulns.command(aliases=['list', 'show'])
@with_appcontext
def ls():
    """List distinct CVEs with their max CVSS score and affected image count."""
    rows = (db.session.query(Vulnerability.cve_id,
                             func.max(Vulnerability.score),
                             func.count(func.distinct(Vulnerability.image_id)))
            .group_by(Vulnerability.cve_id)
            .order_by(func.max(Vulnerability.score).desc().nullslast())
            .all())
    table = [[cve, score if score is not None else '-', images] for cve, score, images in rows]
    click.echo(tabulate(table, headers=['CVE', 'Max CVSS', 'Images']))
