import json
import sys
from dataclasses import dataclass

from flask import render_template, Blueprint

from models.host import Host
from models.image import Image
from models.container import Container

#from server.commands.containers import containers

frontend = Blueprint('frontend', __name__)

@dataclass
class TrivyFindings:
    high: int
    medium: int
    low: int

######### utility functions #########

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
        return None
    trivy_findings = TrivyFindings(0, 0, 0)
    status_trivy = image.status_trivy
    results = status_trivy["Results"]
    for result in results:
        if "Vulnerabilities" in result:
            for vulnerability in result["Vulnerabilities"]:
                severity = vulnerability["Severity"]
                # Where is 'CRITICAL' ?
                if severity == "HIGH":
                    trivy_findings.high += 1
                elif severity == "MEDIUM":
                    trivy_findings.medium += 1
                elif severity == "LOW":
                    trivy_findings.low += 1
    return trivy_findings

def transform_trivy_findings_for_display(image):
    if not image or not image.status_trivy:
        return None

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_findings = []

    status_trivy = image.status_trivy
    results = status_trivy["Results"]
    for result in results:
        if "Vulnerabilities" in result:
            for vulnerability in result["Vulnerabilities"]:
                all_findings.append(vulnerability)

    # Sort findings by severity
    all_findings.sort(key=lambda v: severity_order.get(v.get("Severity", "UNKNOWN"), 4))
    return all_findings

def transform_xeol_findings_for_display(image):
    if not image or not image.status_xeol:
        return None

    all_findings = []
    status_xeol = image.status_xeol
    matches = status_xeol['matches']
    for match in matches:
        if "Cycle" in match:
            all_findings.append({
                'Name': match['Cycle']['ProductName'],
                'Version': match['artifact']['version'],
                'ReleaseDate': match['Cycle']['ReleaseDate'],
                'EolDate': match['Cycle']['Eol'],
            })

    all_findings.sort(key=lambda x: x['EolDate'])
    return all_findings
######### Routes #########

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
            'id': container.id,
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

@frontend.route('/images/<int:image_id>', methods=['GET'])
def get_image_details(image_id):
    image = Image.query.filter(Image.id == image_id).first()
    if not image:
        return "Container not found", 404

    imageData = {
        'id': image.id,
        'name': image.name,
        'repo_digest': image.repo_digest,
        'is_eol': is_image_eol(image),
    }
    trivyFindings = transform_trivy_findings_for_display(image)
    xeolFindings = transform_xeol_findings_for_display(image)

    containers = Container.query.filter(Container.image_id == image_id)
    containerData = []
    for container in containers:
        containerData.append({
            'id': container.id,
            'name': container.name,
            'image': container.image_string,
            'host': container.host.name,
            'status': container.status
            #TODO get container id like "1dddca8476a57d83305787bf5f45d071fe5b143752d416389b25ccd4eda8c6a8" for link to host
        })

    return render_template('image_details.html', containerData=containerData, imageData=imageData, trivyFindings=trivyFindings, xeolFindings=xeolFindings)

@frontend.route('/container/<int:container_id>', methods=['GET'])
def get_container_details(container_id):
    container = Container.query.filter(Container.id == container_id).first()
    if not container:
        return "Container not found", 404

    containerData = {
        'id': container.id,
        'name': container.name,
        'image': container.image_string,
        'image_id': container.image_id,
        'host': container.host.name,
        'status': container.status,
        'started_at': container.started_at,
        'created_at': container.created_at,
        'updated_at': container.updated_at,
    }

    return render_template('container_details.html', containerData=containerData)