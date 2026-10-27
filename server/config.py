import os


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:////data/database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TASK_TRIVY_INTERVAL = int(os.getenv('TASK_TRIVY_INTERVAL', 60))
    TASK_XEOL_INTERVAL = int(os.getenv('TASK_XEOL_INTERVAL', 60))
    TASK_DATA_COLLECTOR_INTERVAL = int(os.getenv('TASK_DATA_COLLECTOR_INTERVAL', 15))
    # Per-image wall-clock limit (seconds) for a single trivy/xeol scan so a hung
    # binary can't block the worker indefinitely.
    TASK_SCAN_TIMEOUT = int(os.getenv('TASK_SCAN_TIMEOUT', 600))
