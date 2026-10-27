from flask import jsonify, Blueprint, render_template
from sqlalchemy.sql import text
from extensions import db
import subprocess
import re

from models.host import Host

general = Blueprint('general', __name__, static_folder='../static')


@general.route('/', methods=['GET'])
def get_home():
    return render_template("index.html")


# Scanner versions change only across deployments, so detect them once and cache
# the result instead of forking two processes on every /health probe (every ~10s).
_tool_versions = None


def _detect_tool_versions():
    global _tool_versions
    if _tool_versions is not None:
        return _tool_versions
    trivy_check = subprocess.run(['trivy', '--version'], capture_output=True, text=True)
    if trivy_check.returncode != 0:
        raise RuntimeError(f'trivy check failed: {trivy_check.stderr}')
    trivy_version = re.sub(r"[^0-9.]", "", trivy_check.stdout.split('\n', 1)[0])
    xeol_check = subprocess.run(['xeol', '--version'], capture_output=True, text=True)
    if xeol_check.returncode != 0:
        raise RuntimeError(f'xeol check failed: {xeol_check.stderr}')
    xeol_version = re.sub(r"[^0-9.]", "", xeol_check.stdout)
    _tool_versions = (trivy_version, xeol_version)
    return _tool_versions


@general.route('/health', methods=['GET'])
def get_health():
    try:
        db.session.execute(text('SELECT 1'))  # live DB liveness check on every call
        trivy_version, xeol_version = _detect_tool_versions()
        return jsonify(
            {'status': 'ok', 'message': f'dockinv server is healthy (xeol {xeol_version}, trivy {trivy_version})'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
