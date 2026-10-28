import secrets
import string
from datetime import date, datetime

from tabulate import tabulate
from extensions import db


def cycle_is_eol(cycle, today=None) -> bool:
    """Whether an xeol release cycle has actually reached end-of-life.

    Xeol lists a cycle whenever it has a *known* EOL date, even when that date
    is still in the future. endoflife.date (xeol's source) encodes ``Eol`` as a
    boolean (already/never EOL) or an ``YYYY-MM-DD`` date. A cycle counts as EOL
    only if the boolean is true or the date is today or in the past.
    """
    eol = (cycle or {}).get("Eol")
    if isinstance(eol, bool):
        return eol
    if isinstance(eol, str):
        try:
            return datetime.strptime(eol, "%Y-%m-%d").date() <= (today or date.today())
        except ValueError:
            return False
    return False


def render_table(model: db.Model, obj: list) -> str:
    columns = [column.name for column in model.__table__.columns]
    table = [[getattr(attr, column) for column in columns] for attr in obj]
    return tabulate(table, columns)


def generate_random_string(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def parse_xeol_to_str(status_xeol) -> str:
    if not status_xeol:
        return "n/a"
    results = []
    matches = status_xeol.get("matches", [])
    for match in matches:
        if cycle_is_eol(match["Cycle"]):
            product_name = match["Cycle"]["ProductName"]
            release_cycle = match["Cycle"]["ReleaseCycle"]
            eol_date = match["Cycle"]["Eol"]
            results.append(f"{product_name} {release_cycle} (EOL {eol_date})")

    if results:
        return "\n".join(results)
    return "OK"


def parse_trivy_to_str(status_trivy) -> str:
    if not status_trivy:
        return "n/a"

    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in status_trivy.get("Results", []):
        for vulnerability in result.get("Vulnerabilities", []):
            severity = vulnerability.get("Severity")
            if severity in severity_count:
                severity_count[severity] += 1

    # CRITICAL is folded into "High" to match the web view (count_trivy_findings_image).
    high = severity_count["CRITICAL"] + severity_count["HIGH"]
    medium, low = severity_count["MEDIUM"], severity_count["LOW"]
    if high + medium + low > 0:
        return f"High: {high}, Medium: {medium}, Low: {low}"
    return "OK"
