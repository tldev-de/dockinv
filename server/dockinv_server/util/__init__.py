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


def parse_xeol_to_str(status_xeol) -> str:
    if not status_xeol:
        return "n/a"
    results = []
    matches = status_xeol.get("matches", [])
    for match in matches:
        if "Eol" in match["Cycle"]:
            productName = match["Cycle"]["ProductName"]
            releaseCycle = match["Cycle"]["ReleaseCycle"]
            eolDate = match["Cycle"]["Eol"]
            results.append(f"{productName} {releaseCycle} (EOL {eolDate})")

    if results:
        return "\n".join(results)
    return "OK"


def parse_trivy_to_str(status_trivy) -> str:
    if not status_trivy:
        return "n/a"

    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in status_trivy.get("Results", []):
        for vulnerability in result.get("Vulnerabilities", []):
            severity = vulnerability.get("Severity")
            if severity in severity_count:
                severity_count[severity] += 1

    high, medium, low = severity_count["HIGH"], severity_count["MEDIUM"], severity_count["LOW"]
    if high + medium + low > 0:
        return f"High: {high}, Medium: {medium}, Low: {low}"
    return "OK"
