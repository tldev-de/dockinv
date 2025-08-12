import json
from dataclasses import dataclass

from flask import render_template, Blueprint

from models.host import Host
from models.image import Image

frontend = Blueprint('frontend', __name__)


def count_eol_images(host):
    eol_images_set = set()  # To ensure each image is counted only once
    for container in host.containers:
        if is_image_eol(container.image):
            eol_images_set.add(container.image.id)  # Use image.id as the unique identifier
    return len(eol_images_set)

def is_image_eol(image):
    if not image.status_xeol:
        return None
    status_xeol = image.status_xeol
    matches = status_xeol.get("matches", [])
    return any("Eol" in match["Cycle"] for match in matches)


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
            image_findings = count_trivy_findings_image(image)
            trivy_findings.high += image_findings.high
            trivy_findings.medium += image_findings.medium
            trivy_findings.low += image_findings.low
    return trivy_findings


def count_trivy_findings_image(image):
    if not image or not image.status_trivy:
        return TrivyFindings(0, 0, 0)
    trivy_findings = TrivyFindings(0, 0, 0)
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
            'id': host.id,
            'name': host.name,
            'last_successful_call': last_call,
            'docker_containers': docker_containers,
            'docker_images': docker_images,
            'eol_images': eol_images,
            'trivy_findings': trivy_findings,
        })

    return render_template('hosts.html', data=data)


@frontend.route('/hosts/<int:host_id>', methods=['GET'])
def get_host(host_id):
    host = Host.query.get(host_id)
    if not host:
        return "Host not found", 404
    data = {
        'host': {
            'id': host.id,
            'name': host.name,
        },
        'containers': [],
    }
    for container in host.containers:
        image = container.image
        data['containers'].append({
            'name': container.name,
            'image': container.image_string,
            'image_hash': container.image.repo_digest,
            'image_eol': is_image_eol(image),
            'trivy_findings': count_trivy_findings_image(image),
        })

    return render_template('host.html', data=data)


@frontend.route('/images', methods=['GET'])
def get_images():
    images = Image.query.filter(Image.containers.any()).all()

    data = []
    for image in images:
        is_eol = is_image_eol(image)
        trivy_findings = count_trivy_findings_image(image)
        usage_count = len(image.containers)

        data.append({
            'id': image.id,
            'image_tags': ', '.join(sorted({c.image_string for c in image.containers})),
            'name': image.name,
            'repo_digest': image.repo_digest,
            'is_eol': is_eol,
            'trivy_findings': trivy_findings,
            'usage_count': usage_count,
        })

    return render_template('images.html', data=data)
