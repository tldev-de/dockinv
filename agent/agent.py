import os
import docker
from flask import Flask, request, jsonify

app = Flask(__name__)

DOCKER_SOCKET = os.getenv('DOCKER_SOCKET', '/var/run/docker.sock')
HTTP_TOKEN = os.getenv('HTTP_TOKEN')
HTTP_PORT = os.getenv('HTTP_PORT', 9999)


@app.route('/containers', methods=['GET'])
def get_docker_containers():
    if HTTP_TOKEN:
        token = request.headers.get('Authorization')
        if token != HTTP_TOKEN:
            return '403 forbidden', 403  # Forbidden

    try:
        client = docker.from_env()
        containers = client.containers.list()
        images = client.images.list()
        image_digests = {image.id: image.attrs['RepoDigests'][0] if len(image.attrs['RepoDigests']) > 0 else None for image in images}
        containers_info = [
            {
                'id': container.id,
                'name': container.name,
                'image_name': container.attrs['Config']['Image'].split(':')[0],
                'image_tag': get_image_tag(container.attrs['Config']['Image']),
                'repo_digest': image_digests.get(container.attrs['Image'], None), # repo digest, NOT image id
                'status': container.status,
                'started_at': container.attrs['State']['StartedAt'],
            }
            for container in containers
        ]
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


def get_image_tag(image):
    parts = image.split(':')
    return parts[1] if len(parts) >= 2 else 'latest'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=HTTP_PORT)
