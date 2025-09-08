from dataclasses import dataclass

from flask import render_template, Blueprint, request, flash, redirect, url_for
from util import generate_random_string
from sqlalchemy import or_

from models.host import Host
from models.image import Image
from models.container import Container

frontend = Blueprint('frontend', __name__)

HOST_NO_FOUND = "Host not found"
CONTAINER_NO_FOUND = "Container not found"

@dataclass
class TrivyFindings:
    high: int
    medium: int
    low: int


######### Functions #########

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
                if severity == "HIGH" or severity == "CRITICAL":
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

### Hosts ###
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
            'enabled': host.enabled,
            'last_successful_call': last_call,
            'docker_containers': docker_containers,
            'docker_images': docker_images,
            'eol_images': eol_images,
            'trivy_findings': trivy_findings,
        })

    return render_template('hosts/hosts.html', data=data)


@frontend.route('/hosts/<int:host_id>', methods=['GET'])
def get_host(host_id):
    host = Host.query.get(host_id)
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for('frontend.add_host'))
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
            'image_id': container.image_id,
            'image_hash': container.image.repo_digest,
            'image_eol': is_image_eol(image),
            'trivy_findings': count_trivy_findings_image(image),
        })

    return render_template('hosts/host.html', data=data)

@frontend.route('/hosts/add', methods=['GET'])
def add_host():
    return render_template('hosts/add.html')

@frontend.route('/hosts/save', methods=['POST'])
def save_host():
    name = request.form['name']
    address = request.form['address']
    token = request.form['token']
    enable = 1 if 'enable' in request.form else 0

    existing = Host.query.filter(or_(Host.name == name, Host.address == address)).first()
    if existing is not None:
        flash('Host with this name or address does already exist!', 'error')
        return redirect(url_for('frontend.add_host'))

    # generate token if not provided
    if token is None or token.strip() == '':
        token = generate_random_string(32)
    # add trailing slash to address if not present
    if address[-1] != '/':
        address += '/'

    host = Host(name=name, address=address, enabled=enable, token=token)
    host.save()

    flash('Host successfully added!', 'success')
    return redirect(url_for('frontend.get_hosts'))

@frontend.route('/hosts/update/<int:host_id>', methods=['POST'])
def update_host(host_id):
    host = Host.query.filter(Host.id == host_id).first()
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for('frontend.get_hosts'))

    host.name = request.form['name']
    host.address = request.form['address']
    host.token = request.form['token']
    host.enabled = 1 if 'enabled' in request.form else 0
    host.save()

    flash('Host successfully updated!', 'success')
    return redirect(url_for('frontend.get_hosts'))

@frontend.route('/hosts/edit/<int:host_id>', methods=['GET'])
def edit_host(host_id):
    host = Host.query.filter(Host.id == host_id).first()
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for('frontend.get_hosts'))

    data = {
        'id': host.id,
        'name': host.name,
        'address': host.address,
        'token': host.token,
        'enabled': host.enabled,
    }

    return render_template('hosts/edit.html', host=data)

@frontend.route('/hosts/delete/<int:host_id>', methods=['GET'])
def delete_host(host_id):
    host = Host.query.filter(Host.id == host_id).first()
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for('frontend.get_hosts'))

    host.delete()

    flash('Host successfully deleted!', 'success')
    return redirect(url_for('frontend.get_hosts'))

### Images ###
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

    return render_template('images/images.html', data=data)

@frontend.route('/images/<int:image_id>', methods=['GET'])
def get_image_details(image_id):
    image = Image.query.filter(Image.id == image_id).first()
    if not image:
        return CONTAINER_NO_FOUND

    image_data = {
        'id': image.id,
        'name': image.name,
        'repo_digest': image.repo_digest,
        'is_eol': is_image_eol(image),
    }
    trivy_findings = transform_trivy_findings_for_display(image)
    xeol_findings = transform_xeol_findings_for_display(image)

    containers = Container.query.filter(Container.image_id == image_id)
    container_data = []
    for container in containers:
        container_data.append({
            'id': container.id,
            'name': container.name,
            'image': container.image_string,
            'host': container.host.name,
            'status': container.status
            #TODO get container id like "1dddca8476a57d83305787bf5f45d071fe5b143752d416389b25ccd4eda8c6a8" for link to host
        })

    return render_template('images/details.html', container_data=container_data, image_data=image_data, trivy_findings=trivy_findings, xeol_findings=xeol_findings)

### Container ###
@frontend.route('/container/<int:container_id>', methods=['GET'])
def get_container_details(container_id):
    container = Container.query.filter(Container.id == container_id).first()
    if not container:
        return CONTAINER_NO_FOUND

    container_data = {
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

    return render_template('container_details.html', container_data=container_data)