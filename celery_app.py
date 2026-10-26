import os
from celery import Celery

broker = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/1")
backend = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/2")

celery_app = Celery(
    "ai_secscan",
    broker=broker,
    backend=backend,
    include=["tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,
    task_soft_time_limit=1500,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)
