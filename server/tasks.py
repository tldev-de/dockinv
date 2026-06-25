import json
import subprocess
import requests
from datetime import datetime, timezone, timedelta

from celery import Celery
from celery.utils.log import get_task_logger
from sqlalchemy import or_, null

from config import Config
from models import Image, Host, Container

celery = Celery('tasks', broker_connection_retry_on_startup=True)

logger = get_task_logger(__name__)


class ContextTask(celery.Task):
    abstract = True
    _app = None

    def __call__(self, *args, **kwargs):
        if ContextTask._app is None:
            from app import create_app
            ContextTask._app = create_app(Config)
        with ContextTask._app.app_context():
            return super(ContextTask, self).__call__(*args, **kwargs)


celery.Task = ContextTask


@celery.on_after_configure.connect
def setup_periodic_tasks(**kwargs):
    celery.add_periodic_task(
        name='trivy_background_task',
        schedule=Config.TASK_TRIVY_INTERVAL * 60,
        sig=celery.signature('tasks.trivy_background_task')
    )
    celery.add_periodic_task(
        name='xeol_background_task',
        schedule=Config.TASK_XEOL_INTERVAL * 60,
        sig=celery.signature('tasks.xeol_background_task')
    )
    celery.add_periodic_task(
        name='data_collector_background_task',
        schedule=Config.TASK_DATA_COLLECTOR_INTERVAL * 60,
        sig=celery.signature('tasks.data_collector_background_task')
    )


@celery.task
def trivy_background_task():
    logger.info(f'Task trivy started at {datetime.now().strftime("%X")}')
    images = (Image.query
              .filter(Image.repo_digest != null())
              .filter(Image.containers.any())  # Only consider images with containers
              .filter(
        or_(Image.updated_at < (datetime.now(tz=timezone.utc) - timedelta(hours=24)), Image.status_trivy == null()))
              .all())
    for image in images:
        logger.info(f'current Image: {image.name} ({image.repo_digest})')
        try:
            result = subprocess.run(
                ['trivy', 'image', image.repo_digest, '--format', 'json'],
                check=True,
                capture_output=True,
                text=True
            )
            image.status_trivy = json.loads(result.stdout)
            image.save()
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running trivy: {e}: {e.stderr}")

    logger.info(f'Task trivy completed at {datetime.now().strftime(format="%X")}')


@celery.task
def xeol_background_task():
    logger.info(f'Task xeol started at {datetime.now().strftime("%X")}')
    images = (Image.query
              .filter(Image.repo_digest != null())
              .filter(Image.containers.any())  # Only consider images with containers
              .filter(
        or_(Image.updated_at < (datetime.now(tz=timezone.utc) - timedelta(hours=24)), Image.status_xeol == null()))
              .all())
    for image in images:
        logger.info(f'current Image: {image.name} ({image.repo_digest})')
        try:
            result = subprocess.run(
                ['xeol', f'{image.repo_digest}', '--output', 'json'],
                check=True,
                capture_output=True,
                text=True
            )
            image.status_xeol = json.loads(result.stdout)
            image.save()
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running xeol: {e}: {e.stderr}")

    logger.info(f'Task xeol completed at {datetime.now().strftime(format="%X")}')


@celery.task
def data_collector_background_task():
    logger.info(f'Task data started at {datetime.now().strftime("%X")}')
    hosts = Host.query.filter_by(enabled=True).all()
    for host in hosts:
        try:
            logger.info(f'current Host: {host.name}')
            r = requests.get(
                host.address + 'containers',
                headers={'Authorization': host.token},
                timeout=(5, 30),
            )
            r.raise_for_status()
            data = r.json()
            logger.debug(f'host output: {data}')

            reported_names = set()
            for c in data:
                reported_names.add(c['name'])
                image = Image.query.filter_by(repo_digest=c['repo_digest']).first()
                if image is None:
                    image = Image(repo_digest=c['repo_digest'], name=c['image_name'])
                    image.save()
                if image.id is None:
                    logger.error(f"Failed to save image {c['image_name']}, skipping container {c['name']}")
                    continue
                container = Container.query.filter_by(name=c['name'], host_id=host.id).first()
                if container is None:
                    container = Container(host_id=host.id, name=c['name'],
                                          image_string=c['image_name'] + ':' + c['image_tag'],
                                          image_id=image.id, status=c['status'],
                                          started_at=datetime.fromisoformat(c['started_at']))
                else:
                    container.image_string = c['image_name'] + ':' + c['image_tag']
                    container.status = c['status']
                    container.started_at = datetime.fromisoformat(c['started_at'])
                container.save()

            # Remove containers that are no longer running on this host
            for stale in Container.query.filter_by(host_id=host.id).all():
                if stale.name not in reported_names:
                    logger.info(f'Removing stale container {stale.name} from host {host.name}')
                    stale.delete()

        except Exception as e:
            logger.error(f'Error processing host {host.name}: {e}')
            continue

    logger.info(f'Task data completed at {datetime.now().strftime("%X")}')
