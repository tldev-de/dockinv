import json
from dataclasses import dataclass

from flask import render_template, Blueprint

from models.host import Host

frontend = Blueprint('frontend', __name__, url_prefix='/app')


def count_eol_images(host):
    eol_images_set = set()  # To ensure each image is counted only once
    for container in host.containers:
        image = container.image
        if image and image.status_xeol:
            status_xeol = image.status_xeol
            matches = status_xeol.get("matches", [])
            if any("Eol" in match["Cycle"] for match in matches):
                eol_images_set.add(image.id)  # Use image.id as the unique identifier
    return len(eol_images_set)


@dataclass
class TrivyFindings:
    high: int
    medium: int
    low: int

def count_trivy_findings(host) -> TrivyFindings:
    trivy_findings = TrivyFindings(0, 0, 0)
    for container in host.containers:
        image = container.image
        if image and image.status_trivy:
            status_trivy = image.status_trivy
            results = status_trivy["Results"]
            for result in results:
                if "Vulnerabilities" in result:
                    for vulnerability in result["Vulnerabilities"]:
                        severity = vulnerability["Severity"]
                        if severity == "HIGH":
                            trivy_findings.high += 1
                        elif severity == "MEDIUM":
                            trivy_findings.medium += 1
                        elif severity == "LOW":
                            trivy_findings.low += 1
    return trivy_findings


@frontend.route('/hosts', methods=['GET'])
def get_hosts():
    hosts = Host.query.all()

    data = []
    for host in hosts:
        last_call = host.updated_at or host.created_at
        docker_containers = len(host.containers)
        docker_images = len(set(container.image_id for container in host.containers))
        eol_images = count_eol_images(host)
        trivy_findings = count_trivy_findings(host)

        data.append({
            'name': host.name,
            'last_successful_call': last_call,
            'docker_containers': docker_containers,
            'docker_images': docker_images,
            'eol_images': eol_images,
            'trivy_findings': trivy_findings,
        })

    return render_template('hosts.html', data=data)
