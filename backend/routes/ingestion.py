import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from models import IngestionSource, SecurityEvent, Tenant, db
from routes.auth import role_required
from services.audit import record_audit
from services.ingestion import normalize_event, process_security_event

ingestion_bp = Blueprint('ingestion', __name__)
SUPPORTED_SOURCE_TYPES = {'syslog', 'windows_event', 'aws_cloudtrail', 'azure_monitor', 'gcp_logging', 'edr', 'firewall', 'api'}


def _source_from_key(api_key):
    if not api_key:
        return None
    for source in IngestionSource.query.filter_by(enabled=True).all():
        if check_password_hash(source.api_key_hash, api_key):
            return source
    return None


@ingestion_bp.route('/ingestion/sources', methods=['GET'])
@jwt_required()
@role_required('admin')
def list_ingestion_sources():
    return jsonify([source.to_dict() for source in IngestionSource.query.order_by(IngestionSource.name).all()])


@ingestion_bp.route('/ingestion/sources', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_ingestion_source():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    source_type = str(data.get('source_type', '')).strip().lower()
    tenant_id = data.get('tenant_id')
    if not name or source_type not in SUPPORTED_SOURCE_TYPES:
        return jsonify({'error': 'name and a supported source_type are required'}), 400
    if IngestionSource.query.filter_by(name=name).first():
        return jsonify({'error': 'An ingestion source with this name already exists'}), 409
    if tenant_id is not None and not Tenant.query.get(tenant_id):
        return jsonify({'error': 'Tenant not found'}), 404
    rate_limit = data.get('rate_limit_per_minute', 600)
    if not isinstance(rate_limit, int) or not 1 <= rate_limit <= 100000:
        return jsonify({'error': 'rate_limit_per_minute must be between 1 and 100000'}), 400
    api_key = secrets.token_urlsafe(32)
    source = IngestionSource(name=name, source_type=source_type, tenant_id=tenant_id,
                             rate_limit_per_minute=rate_limit, api_key_hash=generate_password_hash(api_key))
    db.session.add(source)
    db.session.commit()
    record_audit('system', 'ingestion_source.created', f'ingestion-source/{source.id}')
    return jsonify({**source.to_dict(), 'api_key': api_key}), 201


@ingestion_bp.route('/ingestion/sources/<int:source_id>/rotate-key', methods=['POST'])
@jwt_required()
@role_required('admin')
def rotate_ingestion_key(source_id):
    source = IngestionSource.query.get_or_404(source_id)
    api_key = secrets.token_urlsafe(32)
    source.api_key_hash = generate_password_hash(api_key)
    db.session.commit()
    record_audit('system', 'ingestion_source.key_rotated', f'ingestion-source/{source.id}')
    return jsonify({'id': source.id, 'api_key': api_key})


@ingestion_bp.route('/ingestion/sources/<int:source_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_ingestion_source(source_id):
    source = IngestionSource.query.get_or_404(source_id)
    if SecurityEvent.query.filter_by(source_id=source.id).first():
        source.enabled = False
        db.session.commit()
        record_audit('system', 'ingestion_source.disabled', f'ingestion-source/{source.id}')
        return jsonify({'message': 'Ingestion source disabled because it has retained events'})
    db.session.delete(source)
    db.session.commit()
    record_audit('system', 'ingestion_source.deleted', f'ingestion-source/{source_id}')
    return jsonify({'message': 'Ingestion source deleted'})


@ingestion_bp.route('/ingestion/events', methods=['GET'])
@jwt_required()
@role_required('admin', 'analyst')
def list_security_events():
    query = SecurityEvent.query
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter_by(status=status)
    limit = min(max(request.args.get('limit', 100, type=int), 1), 500)
    return jsonify([event.to_dict() for event in query.order_by(SecurityEvent.created_at.desc()).limit(limit)])


@ingestion_bp.route('/ingest', methods=['POST'])
def ingest_source_event():
    source = _source_from_key(request.headers.get('X-API-Key', ''))
    if source is None:
        return jsonify({'error': 'Invalid ingestion API key'}), 401
    minute_ago = datetime.utcnow() - timedelta(minutes=1)
    event_count = SecurityEvent.query.filter(SecurityEvent.source_id == source.id, SecurityEvent.created_at >= minute_ago).count()
    if event_count >= source.rate_limit_per_minute:
        return jsonify({'error': 'Source rate limit exceeded'}), 429
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'error': 'JSON object required'}), 400
    try:
        normalized, occurred_at = normalize_event(payload, source.source_type)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    winlog = payload.get('winlog') if isinstance(payload.get('winlog'), dict) else {}
    provided_id = payload.get('event_id')
    record_id = payload.get('record_id') or payload.get('EventRecordID') or winlog.get('record_id')
    if provided_id:
        identity = f'{source.id}:event:{provided_id}'
    elif record_id:
        identity = (
            f"{source.id}:{normalized['host']['name'] or ''}:"
            f"{record_id}:{occurred_at.isoformat()}"
        )
    else:
        identity = f'{source.id}:{json.dumps(normalized, sort_keys=True)}'
    event_id = hashlib.sha256(identity.encode()).hexdigest()
    existing = SecurityEvent.query.filter_by(event_id=event_id).first()
    if existing:
        return jsonify({'event_id': existing.event_id, 'status': existing.status, 'duplicate': True}), 202
    event = SecurityEvent(event_id=event_id, source_id=source.id, tenant_id=source.tenant_id,
                          event_type=normalized['event']['kind'], occurred_at=occurred_at,
                          host=normalized['host']['name'], username=normalized['user']['name'],
                          source_ip=normalized['source']['ip'], destination_ip=normalized['destination']['ip'],
                          message=normalized['message'], normalized_event=json.dumps(normalized), raw_event=json.dumps(payload))
    source.last_seen = datetime.utcnow()
    db.session.add(event)
    db.session.commit()
    is_development = os.getenv('ENVIRONMENT', 'development').lower() != 'production'
    if is_development or os.getenv('INGESTION_SYNC_PROCESSING', 'false').lower() == 'true':
        process_security_event.apply(args=(event.event_id,))
        db.session.expire_all()
        event = SecurityEvent.query.filter_by(event_id=event.event_id).first()
    else:
        process_security_event.delay(event.event_id)
    return jsonify({'event_id': event.event_id, 'status': event.status}), 202