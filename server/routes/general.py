from flask import jsonify, Blueprint
from sqlalchemy.sql import text
from extensions import db
import subprocess
import re

from models.host import Host

general = Blueprint('general', __name__, static_folder='../static')


@general.route('/', methods=['GET'])
def get_home():
    return "there is nothing to see yet, please use the cli (see readme)! :)"


@general.route('/health', methods=['GET'])
def get_health():
    try:
        db.session.execute(text('SELECT 1'))
        trivy_check = subprocess.run(['trivy', '--version'], capture_output=True, text=True)
        trivy_version = re.sub(r"[^0-9.]", "", trivy_check.stdout.split('\n', 1)[0])
        if trivy_check.returncode != 0:
            raise Exception(f'trivy check failed: {trivy_check.stderr}')
        xeol_check = subprocess.run(['xeol', '--version'], capture_output=True, text=True)
        xeol_version = re.sub(r"[^0-9.]", "", xeol_check.stdout)
        if xeol_check.returncode != 0:
            raise Exception(f'xeol check failed: {xeol_check.stderr}')
        return jsonify(
            {'status': 'ok', 'message': f'dockinv server is healthy (xeol {xeol_version}, trivy {trivy_version})'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
