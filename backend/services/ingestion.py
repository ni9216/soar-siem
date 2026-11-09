import os
from datetime import datetime, timezone

from models import IngestionSource, SecurityEvent, db
from services.soar_engine import celery

celery.conf.update(
    broker_url=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    result_backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
)


def normalize_event(payload):
    message = str(payload.get('message') or payload.get('log') or '').strip()
    if not message or len(message) > 65536:
        raise ValueError('message is required and must be 64 KB or smaller')

    timestamp = payload.get('timestamp') or payload.get('@timestamp')
    if timestamp:
        try:
            occurred_at = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
            if occurred_at.tzinfo:
                occurred_at = occurred_at.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError as exc:
            raise ValueError('timestamp must be ISO 8601') from exc
    else:
        occurred_at = datetime.utcnow()

    return {
        '@timestamp': occurred_at.isoformat() + 'Z',
        'event': {'kind': str(payload.get('event_type') or payload.get('event', {}).get('kind') or 'event')},
        'message': message,
        'host': {'name': payload.get('host') or payload.get('hostname')},
        'user': {'name': payload.get('username') or payload.get('user', {}).get('name')},
        'source': {'ip': payload.get('source_ip') or payload.get('source', {}).get('ip')},
        'destination': {'ip': payload.get('destination_ip') or payload.get('destination', {}).get('ip')},
    }, occurred_at


@celery.task(name='soar.process_security_event')
def process_security_event(event_id):
    from app import app
    from routes.logs import process_log

    with app.app_context():
        event = SecurityEvent.query.filter_by(event_id=event_id).first()
        if event is None or event.status == 'processed':
            return {'status': 'ignored'}
        event.status = 'processing'
        db.session.commit()
        try:
            source = IngestionSource.query.get(event.source_id)
            response = process_log({'log': event.message}, f'source:{source.name if source else event.source_id}')
            if response.status_code >= 400:
                raise RuntimeError(f'detection pipeline returned HTTP {response.status_code}')
            event.status = 'processed'
            event.processed_at = datetime.utcnow()
            db.session.commit()
            return {'status': 'processed'}
        except Exception as exc:
            db.session.rollback()
            event = SecurityEvent.query.filter_by(event_id=event_id).first()
            event.status = 'failed'
            event.processing_error = str(exc)[:2000]
            db.session.commit()
            raise