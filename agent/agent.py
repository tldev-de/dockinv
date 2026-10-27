import hmac
import os
import docker
from flask import Flask, request, jsonify

app = Flask(__name__)

DOCKER_SOCKET = os.getenv('DOCKER_SOCKET', '/var/run/docker.sock')
HTTP_TOKEN = os.getenv('HTTP_TOKEN')
HTTP_PORT = os.getenv('HTTP_PORT', 9999)
ALLOW_NO_TOKEN = os.getenv('DOCKINV_ALLOW_NO_TOKEN', '').lower() in ('1', 'true', 'yes')

# Refuse to start without a token: an unauthenticated agent exposes the host's
# Docker inventory to anyone who can reach it. Set DOCKINV_ALLOW_NO_TOKEN=1 to
# intentionally run without authentication (e.g. for local testing).
if not HTTP_TOKEN and not ALLOW_NO_TOKEN:
    raise SystemExit(
        'HTTP_TOKEN is not set. The agent refuses to start without authentication. '
        'Set HTTP_TOKEN to a random string (>= 32 chars), or set '
        'DOCKINV_ALLOW_NO_TOKEN=1 to run without authentication on purpose.'
    )


@app.route('/containers', methods=['GET'])
def get_docker_containers():
    if HTTP_TOKEN:
        token = request.headers.get('Authorization', '')
        if not hmac.compare_digest(token, HTTP_TOKEN):
            return '403 forbidden', 403  # Forbidden

    try:
        client = docker.from_env()
        containers = client.containers.list()
        images = client.images.list()
        image_digests = {image.id: image.attrs['RepoDigests'][0] if len(image.attrs['RepoDigests']) > 0 else None for image in images}
        containers_info = []
        for container in containers:
            image_name, image_tag = split_image_ref(container.attrs['Config']['Image'])
            containers_info.append({
                'id': container.id,
                'name': container.name,
                'image_name': image_name,
                'image_tag': image_tag,
                'repo_digest': image_digests.get(container.attrs['Image'], None), # repo digest, NOT image id
                'status': container.status,
                'started_at': container.attrs['State']['StartedAt'],
            })
        return jsonify(containers_info)
    except (docker.errors.APIError, docker.errors.DockerException) as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/health', methods=['GET'])
def get_health():
    try:
        client = docker.from_env()
        client.version()
        return jsonify({'status': 'ok', 'message': 'docker is accessible'})
    except (docker.errors.APIError, docker.errors.DockerException) as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


def split_image_ref(ref):
    """Split a Docker image reference into (name, tag).

    Handles registries with a port (``registry:5000/app:tag``), digests
    (``app@sha256:...``) and tag-less references. A colon only introduces a tag
    when it appears after the last ``/`` (otherwise it is the registry port).
    """
    # Strip an optional digest suffix (``@sha256:...``); it is not the tag.
    ref = ref.split('@', 1)[0]
    last_slash = ref.rfind('/')
    last_colon = ref.rfind(':')
    if last_colon > last_slash:
        return ref[:last_colon], ref[last_colon + 1:]
    return ref, 'latest'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=HTTP_PORT)
