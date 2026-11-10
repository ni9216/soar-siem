import json
import os
from datetime import datetime, timezone

from models import IngestionSource, SecurityEvent, db
from services.soar_engine import celery

celery.conf.update(
    broker_url=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    result_backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
)


SYSMON_EVENT_NAMES = {
    '1': 'ProcessCreate',
    '2': 'FileTimeChanged',
    '3': 'NetworkConnect',
    '5': 'ProcessTerminate',
    '6': 'DriverLoaded',
    '7': 'ImageLoaded',
    '8': 'CreateRemoteThread',
    '10': 'ProcessAccess',
    '11': 'FileCreate',
    '12': 'RegistryObjectCreateOrDelete',
    '13': 'RegistryValueSet',
    '14': 'RegistryKeyOrValueRenamed',
    '15': 'FileCreateStreamHash',
    '17': 'PipeCreated',
    '18': 'PipeConnected',
    '19': 'WmiEventFilter',
    '20': 'WmiEventConsumer',
    '21': 'WmiEventConsumerToFilter',
    '22': 'DnsQuery',
    '23': 'FileDelete',
    '25': 'ProcessTampering',
    '26': 'FileDeleteDetected',
}


def _event_value(mappings, *keys):
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        values = {str(key).casefold(): value for key, value in mapping.items()}
        for key in keys:
            value = values.get(key.casefold())
            if value is not None and value != '':
                return value
    return None


def normalize_event(payload, source_type=None):
    event_block = payload.get('event') if isinstance(payload.get('event'), dict) else {}
    host_block = payload.get('host') if isinstance(payload.get('host'), dict) else {}
    user_block = payload.get('user') if isinstance(payload.get('user'), dict) else {}
    source_block = payload.get('source') if isinstance(payload.get('source'), dict) else {}
    destination_block = payload.get('destination') if isinstance(payload.get('destination'), dict) else {}
    winlog = payload.get('winlog') if isinstance(payload.get('winlog'), dict) else {}
    event_data = (
        payload.get('EventData')
        or payload.get('event_data')
        or winlog.get('event_data')
        or event_block.get('data')
        or {}
    )
    sysmon = source_type == 'windows_event' or any(
        key in payload for key in ('EventID', 'EventData', 'EventRecordID')
    ) or bool(winlog)

    event_code = _event_value(
        [payload, winlog, event_block, event_data],
        'EventID', 'event_id', 'event.code', 'code',
    )
    event_code = str(event_code) if event_code is not None else None
    event_name = SYSMON_EVENT_NAMES.get(event_code, 'WindowsEvent')

    message = str(payload.get('message') or payload.get('log') or '').strip()
    if not message and sysmon:
        if not isinstance(event_data, dict):
            event_data = {'data': event_data}
        message = f"Sysmon {event_name} event {event_code or 'unknown'}: {json.dumps(event_data, sort_keys=True, default=str)}"
    if not message and isinstance(event_block.get('original'), str):
        message = event_block['original'].strip()
    if not message or len(message) > 65536:
        raise ValueError('message is required and must be 64 KB or smaller')

    timestamp = (
        payload.get('timestamp')
        or payload.get('@timestamp')
        or _event_value([payload, event_data], 'UtcTime', 'TimeCreated', 'SystemTime')
    )
    if isinstance(timestamp, dict):
        timestamp = timestamp.get('SystemTime') or timestamp.get('systemTime')
    if timestamp:
        try:
            occurred_at = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
            if occurred_at.tzinfo:
                occurred_at = occurred_at.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError as exc:
            raise ValueError('timestamp must be ISO 8601') from exc
    else:
        occurred_at = datetime.utcnow()

    host_name = _event_value([host_block, payload, event_data], 'name', 'Computer', 'hostname', 'host')
    username = _event_value([user_block, payload, event_data], 'name', 'User', 'username', 'TargetUserName')
    source_ip = _event_value(
        [source_block, payload, event_data], 'ip', 'source_ip', 'SourceIp', 'SourceAddress',
    )
    destination_ip = _event_value(
        [destination_block, payload, event_data], 'ip', 'destination_ip', 'DestinationIp', 'DestinationAddress',
    )

    return {
        '@timestamp': occurred_at.isoformat() + 'Z',
        'event': {
            'kind': (
                f'Sysmon {event_name}'
                if sysmon
                else str(payload.get('event_type') or event_block.get('kind') or 'event')
            ),
            **({'code': event_code, 'action': event_name} if sysmon and event_code else {}),
        },
        'message': message,
        'host': {'name': host_name},
        'user': {'name': username},
        'source': {'ip': source_ip},
        'destination': {'ip': destination_ip},
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