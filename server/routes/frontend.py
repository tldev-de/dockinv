from dataclasses import dataclass

from flask import render_template, Blueprint, request, flash, redirect, url_for
from util import generate_random_string, cycle_is_eol, humanize_age, is_stale
from config import Config
from sqlalchemy import or_, func
from sqlalchemy.orm import selectinload

from extensions import db
from models.host import Host
from models.image import Image
from models.container import Container
from models.vulnerability import Vulnerability

frontend = Blueprint('frontend', __name__)

HOST_NO_FOUND = "Host not found"
CONTAINER_NO_FOUND = "Container not found"
IMAGE_NOT_FOUND = "Image not found"
HOSTS_ROUTE = 'frontend.get_hosts'

@dataclass
class TrivyFindings:
    critical: int
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
    if not image or not image.status_xeol:
        return None
    matches = image.status_xeol.get("matches", [])
    return any(cycle_is_eol(match.get("Cycle", {})) for match in matches)



def count_trivy_findings(host) -> TrivyFindings:
    trivy_findings = TrivyFindings(0, 0, 0, 0)
    counted_images = set()  # dedup per image so a shared image isn't counted twice
    for container in host.containers:
        image = container.image
        if image and image.status_trivy and image.id not in counted_images:
            counted_images.add(image.id)
            image_findings = count_trivy_findings_image(image)
            trivy_findings.critical += image_findings.critical
            trivy_findings.high += image_findings.high
            trivy_findings.medium += image_findings.medium
            trivy_findings.low += image_findings.low
    return trivy_findings


def trivy_sort_weight(findings):
    """A single sortable integer so the multi-number Trivy column sorts by severity
    priority (critical first). ``None`` (not scanned) sorts below any scanned image."""
    if not findings:
        return -1
    return (findings.critical * 1_000_000_000 + findings.high * 1_000_000
            + findings.medium * 1_000 + findings.low)


def count_trivy_findings_image(image):
    if not image or not image.status_trivy:
        return None
    trivy_findings = TrivyFindings(0, 0, 0, 0)
    status_trivy = image.status_trivy
    results = status_trivy["Results"]
    for result in results:
        if "Vulnerabilities" in result:
            for vulnerability in result["Vulnerabilities"]:
                severity = vulnerability["Severity"]
                if severity == "CRITICAL":
                    trivy_findings.critical += 1
                elif severity == "HIGH":
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
    matches = status_xeol.get('matches', [])
    for match in matches:
        if "Cycle" in match:
            all_findings.append({
                'Name': match['Cycle']['ProductName'],
                'Version': match['artifact']['version'],
                'ReleaseDate': match['Cycle']['ReleaseDate'],
                'EolDate': match['Cycle']['Eol'],
                'IsEol': cycle_is_eol(match['Cycle']),  # past-EOL vs. still-supported
            })

    all_findings.sort(key=lambda x: x['EolDate'])
    return all_findings

######### Routes #########

### Dashboard ###
def _dashboard_overview():
    hosts = Host.query.options(
        selectinload(Host.containers).selectinload(Container.image)
    ).all()
    in_use_image_ids = {row[0] for row in db.session.query(Container.image_id).distinct()}
    images = (Image.query.filter(Image.id.in_(in_use_image_ids)).all()
              if in_use_image_ids else [])

    # distinct CVEs per severity across in-use images (matches /vulnerabilities semantics)
    sev_sets = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    if in_use_image_ids:
        for v in Vulnerability.query.filter(Vulnerability.image_id.in_(in_use_image_ids)).all():
            if v.severity in sev_sets:
                sev_sets[v.severity].add(v.cve_id)

    worst = []
    for img in images:
        findings = count_trivy_findings_image(img)
        eol = is_image_eol(img)
        if findings is None and not eol:
            continue  # not scanned and not EOL -> nothing to show
        worst.append({'id': img.id, 'name': img.name, 'eol': eol,
                      'findings': findings, 'usage': len(img.containers)})
    worst.sort(key=lambda w: (w['findings'].critical if w['findings'] else 0,
                              w['findings'].high if w['findings'] else 0,
                              w['findings'].medium if w['findings'] else 0,
                              bool(w['eol'])), reverse=True)

    last_calls = [h.last_seen for h in hosts if h.last_seen]
    return {
        'host_total': len(hosts),
        'host_enabled': sum(1 for h in hosts if h.enabled),
        'never_reported': sum(1 for h in hosts if h.enabled and h.last_seen is None),
        'container_total': Container.query.count(),
        'image_total': len(images),
        'eol_total': sum(1 for img in images if is_image_eol(img)),
        'severities': {k.lower(): len(s) for k, s in sev_sets.items()},
        'last_collection': humanize_age(max(last_calls)) if last_calls else None,
        'worst_images': worst[:5],
    }


@frontend.route('/', methods=['GET'])
def dashboard():
    return render_template('index.html', data=_dashboard_overview())


### Hosts ###
def _hosts_overview():
    hosts = Host.query.options(
        selectinload(Host.containers).selectinload(Container.image)
    ).all()

    # An enabled host that hasn't reported within a few collection cycles is likely
    # broken (agent down, token/network issue); flag it instead of showing a stale number.
    stale_after = 3 * Config.TASK_DATA_COLLECTOR_INTERVAL  # minutes

    data = []
    for host in hosts:
        docker_containers = len(host.containers)
        docker_images = len(set(container.image_id for container in host.containers))
        eol_images = count_eol_images(host)
        trivy_findings = count_trivy_findings(host)

        data.append({
            'id': host.id,
            'name': host.name,
            'enabled': host.enabled,
            'last_successful_call': humanize_age(host.last_seen),
            'stale': host.enabled and is_stale(host.last_seen, stale_after),
            'docker_containers': docker_containers,
            'docker_images': docker_images,
            'eol_images': eol_images,
            'trivy_findings': trivy_findings,
            'trivy_sort': trivy_sort_weight(trivy_findings),
        })
    return data


@frontend.route('/hosts', methods=['GET'])
def get_hosts():
    return render_template('hosts/hosts.html', data=_hosts_overview())


@frontend.route('/hosts/table', methods=['GET'])
def get_hosts_table():
    """HTMX partial: just the hosts table (used for polling / live refresh)."""
    return render_template('hosts/_hosts_table.html', data=_hosts_overview())


@frontend.route('/hosts/collect', methods=['POST'])
def collect_hosts():
    """HTMX: trigger an on-demand data collection, show a toast, and schedule a
    one-shot refresh so the freshly collected data appears without a manual reload."""
    from tasks import data_collector_background_task
    try:
        data_collector_background_task.delay()
        toast = {'message': 'Collection queued — refreshing in a moment…',
                 'refresh_url': url_for('frontend.get_hosts_table'),
                 'refresh_target': '#hostTable', 'refresh_delay': 3}
    except Exception as e:  # broker unreachable from the web process
        toast = {'message': f'Could not trigger collection: {e}', 'category': 'error'}
    return (render_template('hosts/_hosts_table.html', data=_hosts_overview())
            + render_template('_toast.html', **toast))


@frontend.route('/hosts/<int:host_id>', methods=['GET'])
def get_host(host_id):
    host = Host.query.filter(Host.id == host_id).first()
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for(HOSTS_ROUTE))
    data = {
        'host': {
            'id': host.id,
            'name': host.name,
        },
        'containers': [],
    }
    for container in host.containers:
        image = container.image
        findings = count_trivy_findings_image(image)
        data['containers'].append({
            'name': container.name,
            'id': container.id,
            'status': container.status,
            'image': container.image_string,
            'image_id': container.image_id,
            'image_hash': container.image.repo_digest,
            'image_eol': is_image_eol(image),
            'trivy_findings': findings,
            'trivy_sort': trivy_sort_weight(findings),
            'stack': container.stack,
            'hostnames': container.hostnames.split(', ') if container.hostnames else [],
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
    enable = 'enabled' in request.form

    if not address:
        flash('Address is required.', 'error')
        return redirect(url_for('frontend.add_host'))

    existing = Host.query.filter(or_(Host.name == name, Host.address == address)).first()
    if existing is not None:
        flash('Host with this name or address does already exist!', 'error')
        return redirect(url_for('frontend.add_host'))

    if not token or token.strip() == '':
        token = generate_random_string(32)
    if address[-1] != '/':
        address += '/'

    host = Host(name=name, address=address, enabled=enable, token=token)
    host.save()

    flash('Host successfully added!', 'success')
    return redirect(url_for(HOSTS_ROUTE))

@frontend.route('/hosts/update/<int:host_id>', methods=['POST'])
def update_host(host_id):
    host = Host.query.filter(Host.id == host_id).first()
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for(HOSTS_ROUTE))

    address = request.form['address']
    if not address:
        flash('Address is required.', 'error')
        return redirect(url_for(HOSTS_ROUTE))
    if address[-1] != '/':
        address += '/'
    token = request.form.get('token', '').strip()
    if not token:
        token = generate_random_string(32)
    host.name = request.form['name']
    host.address = address
    host.token = token
    host.enabled = 'enabled' in request.form
    host.save()

    flash('Host successfully updated!', 'success')
    return redirect(url_for(HOSTS_ROUTE))

@frontend.route('/hosts/edit/<int:host_id>', methods=['GET'])
def edit_host(host_id):
    host = Host.query.filter(Host.id == host_id).first()
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for(HOSTS_ROUTE))

    data = {
        'id': host.id,
        'name': host.name,
        'address': host.address,
        'token': host.token,
        'enabled': host.enabled,
    }

    return render_template('hosts/edit.html', host=data)

@frontend.route('/hosts/delete/<int:host_id>', methods=['POST'])
def delete_host(host_id):
    host = Host.query.filter(Host.id == host_id).first()
    if not host:
        flash(HOST_NO_FOUND, 'error')
        return redirect(url_for(HOSTS_ROUTE))

    host.delete()

    flash('Host successfully deleted!', 'success')
    return redirect(url_for(HOSTS_ROUTE))

### Images ###
def _images_overview():
    data = []
    for image in Image.query.filter(Image.containers.any()).all():
        data.append({
            'id': image.id,
            'image_tags': ', '.join(sorted({c.image_string for c in image.containers})),
            'name': image.name,
            'repo_digest': image.repo_digest,
            'is_eol': is_image_eol(image),
            'trivy_findings': count_trivy_findings_image(image),
            'trivy_sort': trivy_sort_weight(count_trivy_findings_image(image)),
            'scanned': humanize_age(image.updated_at),  # updated_at == last scan (never until first)
            'usage_count': len(image.containers),
        })
    return data


@frontend.route('/images', methods=['GET'])
def get_images():
    return render_template('images/images.html', data=_images_overview())


@frontend.route('/images/table', methods=['GET'])
def get_images_table():
    """HTMX partial: just the images table."""
    return render_template('images/_images_table.html', data=_images_overview())


@frontend.route('/images/scan', methods=['POST'])
def scan_images():
    """HTMX: trigger an on-demand Trivy + Xeol scan, then return the refreshed table.

    The scan tasks pick up images that are new or stale (>24h); results appear on
    the next refresh since scanning runs asynchronously in the worker.
    """
    try:
        from tasks import trivy_background_task, xeol_background_task
        trivy_background_task.delay()
        xeol_background_task.delay()
        toast = {'message': 'Scan queued — results appear as scans finish (can take a few minutes).',
                 'refresh_url': url_for('frontend.get_images_table'),
                 'refresh_target': '#imagesTable', 'refresh_delay': 6}
    except Exception as e:  # broker unreachable from the web process
        toast = {'message': f'Could not trigger scan: {e}', 'category': 'error'}
    return (render_template('images/_images_table.html', data=_images_overview())
            + render_template('_toast.html', **toast))

@frontend.route('/images/<int:image_id>', methods=['GET'])
def get_image_details(image_id):
    image = Image.query.filter(Image.id == image_id).first()
    if not image:
        flash(IMAGE_NOT_FOUND, 'error')
        return redirect(url_for('frontend.get_images'))

    image_data = {
        'id': image.id,
        'name': image.name,
        'repo_digest': image.repo_digest,
        'is_eol': is_image_eol(image),
        'scanned': humanize_age(image.updated_at),
        'trivy_scanned': image.status_trivy is not None,
        'xeol_scanned': image.status_xeol is not None,
    }
    trivy_findings = transform_trivy_findings_for_display(image)
    xeol_findings = transform_xeol_findings_for_display(image)

    containers = Container.query.filter(Container.image_id == image_id).all()
    container_data = []
    for container in containers:
        container_data.append({
            'id': container.id,
            'name': container.name,
            'image': container.image_string,
            'host': container.host.name,
            'status': container.status
        })

    return render_template('images/details.html', container_data=container_data, image_data=image_data, trivy_findings=trivy_findings, xeol_findings=xeol_findings)

### Container ###
@frontend.route('/container/<int:container_id>', methods=['GET'])
def get_container_details(container_id):
    container = Container.query.filter(Container.id == container_id).first()
    if not container:
        flash(CONTAINER_NO_FOUND, 'error')
        return redirect(url_for(HOSTS_ROUTE))

    container_data = {
        'id': container.id,
        'name': container.name,
        'image': container.image_string,
        'image_id': container.image_id,
        'host': container.host.name,
        'status': container.status,
        'stack': container.stack,
        'hostnames': container.hostnames.split(', ') if container.hostnames else [],
        'started_at': container.started_at,
        'created_at': container.created_at,
        'updated_at': container.updated_at,
    }

    return render_template('container_details.html', container_data=container_data)


### Vulnerabilities ###
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _rank(severity):
    return _SEVERITY_RANK.get(severity, 4)


def _parse_vuln_filters(args):
    cve = (args.get('cve') or '').strip()
    severity = (args.get('severity') or '').strip().upper()
    raw_cvss = (args.get('min_cvss') or '').strip()
    try:
        min_cvss = float(raw_cvss) if raw_cvss else None
    except ValueError:
        min_cvss = None
    only_fixable = (args.get('fixable') or '').strip().lower() in ('1', 'true', 'on', 'yes')
    return cve, severity, min_cvss, only_fixable


def _vulnerabilities_overview(cve='', severity='', min_cvss=None, only_fixable=False):
    # Only images that actually run somewhere count as "vulnerable containers".
    container_counts = dict(
        db.session.query(Container.image_id, func.count(Container.id))
        .group_by(Container.image_id).all()
    )
    image_names = dict(db.session.query(Image.id, Image.name).all())

    query = Vulnerability.query
    if cve:
        query = query.filter(Vulnerability.cve_id.ilike(f'%{cve}%'))

    agg = {}
    for v in query.all():
        if container_counts.get(v.image_id, 0) == 0:
            continue
        entry = agg.get(v.cve_id)
        if entry is None:
            entry = agg[v.cve_id] = {'id': v.cve_id, 'severity': v.severity, 'score': v.score,
                                     'images': set(), 'packages': set(), 'fixable': False}
        entry['images'].add(v.image_id)
        if v.pkg_name:
            entry['packages'].add(v.pkg_name)
        entry['fixable'] = entry['fixable'] or bool(v.fixed_version)
        if _rank(v.severity) < _rank(entry['severity']):
            entry['severity'] = v.severity
        if v.score is not None and (entry['score'] is None or v.score > entry['score']):
            entry['score'] = v.score

    data = []
    for e in agg.values():
        if severity and _rank(e['severity']) > _rank(severity):
            continue  # keep only CVEs at or above the selected minimum severity
        if min_cvss is not None and (e['score'] is None or e['score'] < min_cvss):
            continue
        if only_fixable and not e['fixable']:
            continue  # keep only CVEs with a fixed version available somewhere
        data.append({
            'id': e['id'], 'severity': e['severity'], 'score': e['score'],
            'fixable': e['fixable'],
            'packages': ', '.join(sorted(e['packages'])),
            'images': ', '.join(sorted({image_names.get(i, '?') for i in e['images']})),
            'image_count': len(e['images']),
            'container_count': sum(container_counts[i] for i in e['images']),
        })
    data.sort(key=lambda d: (d['score'] is None, -(d['score'] or 0), _rank(d['severity']), d['id']))
    return data


@frontend.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    cve, severity, min_cvss, only_fixable = _parse_vuln_filters(request.args)
    data = _vulnerabilities_overview(cve, severity, min_cvss, only_fixable)
    return render_template('vulnerabilities/list.html', data=data,
                           cve=cve, severity=severity, min_cvss=request.args.get('min_cvss', ''),
                           fixable=only_fixable)


@frontend.route('/vulnerabilities/table', methods=['GET'])
def get_vulnerabilities_table():
    """HTMX partial: the filtered vulnerability table."""
    cve, severity, min_cvss, only_fixable = _parse_vuln_filters(request.args)
    return render_template('vulnerabilities/_table.html',
                           data=_vulnerabilities_overview(cve, severity, min_cvss, only_fixable))


@frontend.route('/vulnerabilities/<cve_id>', methods=['GET'])
def get_vulnerability_detail(cve_id):
    vulns = (Vulnerability.query.filter_by(cve_id=cve_id)
             .options(selectinload(Vulnerability.image)
                      .selectinload(Image.containers)
                      .selectinload(Container.host))
             .all())

    header = {'id': cve_id, 'severity': None, 'score': None, 'url': None}
    rows = []
    for v in vulns:
        if header['severity'] is None or _rank(v.severity) < _rank(header['severity']):
            header['severity'] = v.severity
        if v.score is not None and (header['score'] is None or v.score > header['score']):
            header['score'] = v.score
        if not header['url'] and v.primary_url:
            header['url'] = v.primary_url
        for container in v.image.containers:
            rows.append({
                'host': container.host.name,
                'container': container.name,
                'container_id': container.id,
                'image': container.image_string,
                'image_id': v.image_id,
                'pkg': v.pkg_name,
                'installed': v.installed_version,
                'fixed': v.fixed_version,
                'severity': v.severity,
                'score': v.score,
            })

    if not rows:
        flash(f'No running containers affected by {cve_id}.', 'info')
        return redirect(url_for('frontend.get_vulnerabilities'))
    rows.sort(key=lambda r: (r['host'], r['container']))
    return render_template('vulnerabilities/detail.html', cve=header, rows=rows)