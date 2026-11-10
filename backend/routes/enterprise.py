import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import text

from models import (
    AlertGroup,
    Asset,
    AuditLog,
    Case,
    DetectionRule,
    Incident,
    LogSource,
    PlaybookExecution,
    SecurityEvent,
    SecuritySetting,
    Tenant,
    User,
    db,
)
from routes.auth import get_current_user, role_required
from services.audit import record_audit
from services.incident_workflow import append_incident_timeline
from services.playbook_safety import (
    WORKFLOW_ACTIONS,
    create_approved_execution,
    validate_actions,
)

enterprise_bp = Blueprint('enterprise', __name__)


def _actor():
    return get_jwt_identity() or 'system'


def _setting(key, default=False):
    setting = SecuritySetting.query.get(key)
    if setting is None:
        return default
    return setting.value.lower() == 'true'


def _set_setting(key, value):
    setting = SecuritySetting.query.get(key)
    if setting is None:
        setting = SecuritySetting(key=key, value=str(value).lower())
        db.session.add(setting)
    else:
        setting.value = str(value).lower()
    db.session.commit()
    return setting


@enterprise_bp.route('/audit-logs', methods=['GET'])
@jwt_required()
@role_required('admin')
def list_audit_logs():
    query = AuditLog.query
    actor = request.args.get('actor', '').strip()
    action = request.args.get('action', '').strip()
    if actor:
        query = query.filter_by(actor=actor)
    if action:
        query = query.filter_by(action=action)
    limit = min(max(request.args.get('limit', 100, type=int), 1), 500)
    return jsonify([entry.to_dict() for entry in query.order_by(AuditLog.created_at.desc()).limit(limit)])


@enterprise_bp.route('/security-policy', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_security_policy():
    return jsonify({'require_admin_mfa': _setting('require_admin_mfa')})


@enterprise_bp.route('/security-policy', methods=['PUT'])
@jwt_required()
@role_required('admin')
def update_security_policy():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('require_admin_mfa'), bool):
        return jsonify({'error': 'require_admin_mfa must be a boolean'}), 400
    _set_setting('require_admin_mfa', data['require_admin_mfa'])
    record_audit(_actor(), 'security_policy.updated', 'security-policy', details=data)
    return jsonify({'require_admin_mfa': data['require_admin_mfa']})


@enterprise_bp.route('/alert-groups', methods=['GET'])
@jwt_required()
def list_alert_groups():
    query = AlertGroup.query
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter_by(status=status)
    return jsonify([group.to_dict() for group in query.order_by(AlertGroup.last_seen.desc()).all()])


@enterprise_bp.route('/alert-groups/<int:group_id>/assign', methods=['PUT'])
@jwt_required()
@role_required('admin', 'analyst')
def assign_alert_group(group_id):
    data = request.get_json(silent=True) or {}
    user_id = data.get('assigned_to')
    if user_id is not None and not User.query.get(user_id):
        return jsonify({'error': 'Assigned user not found'}), 404
    group = AlertGroup.query.get_or_404(group_id)
    group.assigned_to = user_id
    group.status = data.get('status', group.status)
    db.session.commit()
    record_audit(_actor(), 'alert_group.assigned', f'alert-group/{group.id}', details={'assigned_to': user_id})
    return jsonify(group.to_dict())


@enterprise_bp.route('/alert-deduplication', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_alert_deduplication():
    setting = SecuritySetting.query.get('alert_dedup_window_minutes')
    try:
        window_minutes = int(setting.value) if setting else 5
    except ValueError:
        current_app.logger.error("Invalid alert_dedup_window_minutes setting")
        window_minutes = 5
    return jsonify({'window_minutes': window_minutes})


@enterprise_bp.route('/alert-deduplication', methods=['PUT'])
@jwt_required()
@role_required('admin')
def update_alert_deduplication():
    data = request.get_json(silent=True)
    window_minutes = data.get('window_minutes') if isinstance(data, dict) else None
    if isinstance(window_minutes, bool) or not isinstance(window_minutes, int) or not 0 <= window_minutes <= 1440:
        return jsonify({'error': 'window_minutes must be an integer between 0 and 1440'}), 400
    _set_setting('alert_dedup_window_minutes', window_minutes)
    record_audit(_actor(), 'alert_deduplication.updated', 'alert-deduplication', details={
        'window_minutes': window_minutes,
    })
    return jsonify({'window_minutes': window_minutes})


@enterprise_bp.route('/assets/<int:asset_id>/log-sources', methods=['GET'])
@jwt_required()
def list_asset_log_sources(asset_id):
    Asset.query.get_or_404(asset_id)
    sources = LogSource.query.filter_by(asset_id=asset_id).order_by(LogSource.name).all()
    return jsonify([source.to_dict() for source in sources])


@enterprise_bp.route('/assets/<int:asset_id>/log-sources', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def create_log_source(asset_id):
    Asset.query.get_or_404(asset_id)
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    connector_type = str(data.get('connector_type', '')).strip().lower()
    if not name or connector_type not in {'syslog', 'windows_event', 'aws_cloudtrail', 'azure_monitor', 'gcp_logging', 'api'}:
        return jsonify({'error': 'A name and supported connector_type are required'}), 400
    source = LogSource(
        asset_id=asset_id,
        name=name,
        connector_type=connector_type,
        status='active',
        configuration=json.dumps(data.get('configuration', {})),
        last_sync=datetime.utcnow(),
    )
    db.session.add(source)
    db.session.commit()
    record_audit(_actor(), 'log_source.created', f'log-source/{source.id}', details={'asset_id': asset_id})
    return jsonify(source.to_dict()), 201


@enterprise_bp.route('/log-sources/<int:source_id>/sync', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def sync_log_source(source_id):
    source = LogSource.query.get_or_404(source_id)
    source.last_sync = datetime.utcnow()
    source.status = 'active'
    db.session.commit()
    record_audit(_actor(), 'log_source.sync_requested', f'log-source/{source.id}')
    return jsonify(source.to_dict())


def _validate_rule_payload(data):
    name = str(data.get('name', '')).strip()
    pattern = str(data.get('pattern', '')).strip()
    severity = str(data.get('severity', 'Medium')).title()
    if not name or not pattern:
        return None, jsonify({'error': 'name and pattern are required'}), 400
    if len(name) > 120 or len(pattern) > 500:
        return None, jsonify({'error': 'name or pattern is too long'}), 400
    if severity not in {'Low', 'Medium', 'High', 'Critical'}:
        return None, jsonify({'error': 'Invalid severity'}), 400
    return {'name': name, 'pattern': pattern, 'severity': severity}, None, None


@enterprise_bp.route('/rules', methods=['GET'])
@jwt_required()
def list_detection_rules():
    return jsonify([rule.to_dict() for rule in DetectionRule.query.order_by(DetectionRule.name).all()])


@enterprise_bp.route('/rules', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def create_detection_rule():
    data = request.get_json(silent=True) or {}
    values, error, status = _validate_rule_payload(data)
    if error:
        return error, status
    if DetectionRule.query.filter_by(name=values['name']).first():
        return jsonify({'error': 'A rule with this name already exists'}), 409
    rule = DetectionRule(
        **values,
        description=str(data.get('description', ''))[:2000],
        mitre_attack_id=str(data.get('mitre_attack_id', '')).strip() or None,
        enabled=bool(data.get('enabled', True)),
    )
    db.session.add(rule)
    db.session.commit()
    record_audit(_actor(), 'detection_rule.created', f'rule/{rule.id}')
    return jsonify(rule.to_dict()), 201


@enterprise_bp.route('/rules/<int:rule_id>', methods=['PUT'])
@jwt_required()
@role_required('admin', 'analyst')
def update_detection_rule(rule_id):
    rule = DetectionRule.query.get_or_404(rule_id)
    data = request.get_json(silent=True) or {}
    values, error, status = _validate_rule_payload({
        'name': data.get('name', rule.name),
        'pattern': data.get('pattern', rule.pattern),
        'severity': data.get('severity', rule.severity),
    })
    if error:
        return error, status
    duplicate = DetectionRule.query.filter(DetectionRule.name == values['name'], DetectionRule.id != rule.id).first()
    if duplicate:
        return jsonify({'error': 'A rule with this name already exists'}), 409
    for key, value in values.items():
        setattr(rule, key, value)
    for key in ('description', 'mitre_attack_id', 'enabled'):
        if key in data:
            setattr(rule, key, data[key])
    rule.version += 1
    db.session.commit()
    record_audit(_actor(), 'detection_rule.updated', f'rule/{rule.id}', details={'version': rule.version})
    return jsonify(rule.to_dict())


@enterprise_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin', 'analyst')
def delete_detection_rule(rule_id):
    rule = DetectionRule.query.get_or_404(rule_id)
    rule_name = rule.name
    db.session.delete(rule)
    db.session.commit()
    record_audit(_actor(), 'detection_rule.deleted', f'rule/{rule_id}', details={'name': rule_name})
    return jsonify({'message': 'Detection rule deleted'})


@enterprise_bp.route('/rules/<int:rule_id>/test', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def test_detection_rule(rule_id):
    rule = DetectionRule.query.get_or_404(rule_id)
    data = request.get_json(silent=True) or {}
    log = str(data.get('log', ''))
    if not log:
        return jsonify({'error': 'log is required'}), 400
    matched = rule.pattern.casefold() in log.casefold()
    record_audit(_actor(), 'detection_rule.tested', f'rule/{rule.id}', details={'matched': matched})
    return jsonify({'rule_id': rule.id, 'matched': matched, 'severity': rule.severity if matched else None})


@enterprise_bp.route('/rules/coverage', methods=['GET'])
@jwt_required()
def mitre_coverage():
    rules = DetectionRule.query.filter_by(enabled=True).all()
    coverage = {}
    for rule in rules:
        if rule.mitre_attack_id:
            coverage.setdefault(rule.mitre_attack_id, []).append(rule.name)
    return jsonify({'covered_techniques': coverage, 'coverage_count': len(coverage), 'enabled_rule_count': len(rules)})


def _execute_playbook(execution):
    incident = Incident.query.get(execution.incident_id)
    if incident is None:
        execution.status = 'failed'
        execution.result = json.dumps({'error': 'Incident no longer exists'})
        db.session.commit()
        return execution

    if not execution.requires_approval or execution.approved_at is None:
        raise ValueError('Playbook execution requires an administrator approval')

    actions, error = validate_actions(json.loads(execution.actions or '[]'))
    if error:
        execution.status = 'failed'
        execution.result = json.dumps({'error': error})
        db.session.commit()
        return execution

    previous_status = incident.status
    execution.status = 'running'
    db.session.commit()

    action_results = {}
    manual_actions = []
    if any(action in WORKFLOW_ACTIONS for action in actions):
        if 'escalation' in actions:
            incident.status = 'escalated'
        else:
            incident.status = 'investigating'
        if 'containment' in actions:
            manual_actions.append('Host isolation and network blocking require a configured integration and operator action.')
        if 'investigation' in actions:
            manual_actions.append('Evidence collection is not configured; continue the investigation manually.')

    if 'escalate' in actions:
        incident.status = 'escalated'
    if 'notify_slack' in actions or 'notify_discord' in actions or 'notify_email' in actions:
        from services.notifications import send_discord, send_email, send_slack

        message = (
            f"Incident #{incident.id}\n"
            f"Severity: {incident.severity}\n"
            f"Title: {incident.title}\n"
            f"Details: {incident.details or ''}"
        )
        if 'notify_slack' in actions:
            action_results['notify_slack'] = send_slack(message, incident.severity)
        if 'notify_discord' in actions:
            action_results['notify_discord'] = send_discord(message, incident.severity)
        if 'notify_email' in actions:
            recipients = [
                user.email for user in User.query.filter_by(notify_email=True).all()
                if user.email
            ]
            action_results['notify_email'] = {
                'recipients': len(recipients),
                'sent': sum(
                    1 for recipient in recipients
                    if send_email(recipient, f"[{incident.severity}] {incident.title}", message)
                ),
            }

    append_incident_timeline(
        incident,
        execution.approved_by or 'system',
        'playbook_executed',
        {'execution_id': execution.id, 'playbook': execution.playbook},
    )
    result = {
        'execution_mode': 'approved',
        'planned_actions': actions,
        'action_results': action_results,
        'manual_actions_required': manual_actions,
        'previous_incident_status': previous_status,
        'incident_status_after': incident.status,
        'external_actions_reversed_by_rollback': False,
    }
    execution.status = 'completed'
    execution.result = json.dumps(result)
    execution.completed_at = datetime.utcnow()
    db.session.commit()
    return execution


@enterprise_bp.route('/soar/executions', methods=['GET'])
@jwt_required()
def list_playbook_executions():
    query = PlaybookExecution.query
    incident_id = request.args.get('incident_id', type=int)
    if incident_id:
        query = query.filter_by(incident_id=incident_id)
    return jsonify([execution.to_dict() for execution in query.order_by(PlaybookExecution.created_at.desc()).all()])


@enterprise_bp.route('/soar/executions', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def create_playbook_execution():
    data = request.get_json(silent=True) or {}
    incident_id = data.get('incident_id')
    playbook = data.get('playbook', 'investigation')
    if not isinstance(incident_id, int) or incident_id <= 0:
        return jsonify({'error': 'incident_id is required'}), 400
    if not isinstance(playbook, str) or playbook.lower() not in WORKFLOW_ACTIONS:
        return jsonify({'error': 'Unsupported playbook'}), 400
    incident = Incident.query.get_or_404(incident_id)
    dry_run = data.get('dry_run', False)
    if not isinstance(dry_run, bool):
        return jsonify({'error': 'dry_run must be a boolean'}), 400
    execution = create_approved_execution(
        incident,
        playbook.lower(),
        _actor(),
        [playbook.lower()],
        dry_run=dry_run,
    )
    record_audit(
        _actor(),
        'soar.execution_previewed' if dry_run else 'soar.execution_requested',
        f'execution/{execution.id}',
        details={'requires_approval': not dry_run},
    )
    return jsonify(execution.to_dict()), 200 if dry_run else 202


@enterprise_bp.route('/soar/executions/<int:execution_id>/approve', methods=['POST'])
@jwt_required()
@role_required('admin')
def approve_playbook_execution(execution_id):
    execution = PlaybookExecution.query.with_for_update().get_or_404(execution_id)
    if execution.status != 'pending_approval':
        return jsonify({'error': 'Execution is not awaiting approval'}), 409
    execution.approved_at = datetime.utcnow()
    execution.approved_by = _actor()
    execution.status = 'pending'
    db.session.commit()
    _execute_playbook(execution)
    record_audit(_actor(), 'soar.execution_approved', f'execution/{execution.id}')
    return jsonify(execution.to_dict())


@enterprise_bp.route('/soar/executions/<int:execution_id>/reject', methods=['POST'])
@jwt_required()
@role_required('admin')
def reject_playbook_execution(execution_id):
    execution = PlaybookExecution.query.with_for_update().get_or_404(execution_id)
    if execution.status != 'pending_approval':
        return jsonify({'error': 'Execution is not awaiting approval'}), 409
    execution.status = 'rejected'
    execution.completed_at = datetime.utcnow()
    execution.result = json.dumps({'rejected_by': _actor(), 'external_actions_performed': False})
    db.session.commit()
    record_audit(_actor(), 'soar.execution_rejected', f'execution/{execution.id}')
    return jsonify(execution.to_dict())


@enterprise_bp.route('/soar/executions/<int:execution_id>/rollback', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def rollback_playbook_execution(execution_id):
    execution = PlaybookExecution.query.get_or_404(execution_id)
    if execution.status != 'completed':
        return jsonify({'error': 'Only completed executions can be rolled back'}), 409
    incident = Incident.query.get(execution.incident_id)
    result = json.loads(execution.result or '{}')
    status_restored = False
    if incident:
        if incident.status == result.get('incident_status_after'):
            incident.status = result.get('previous_incident_status', incident.status)
            status_restored = True
        append_incident_timeline(
            incident,
            _actor(),
            'playbook_rollback_recorded',
            {'execution_id': execution.id, 'incident_status_restored': status_restored},
        )
    execution.status = 'rollback_required'
    result['rollback'] = {
        'incident_status_restored': status_restored,
        'external_actions_reversed': False,
        'message': 'Review and reverse any external notification or integration action manually.',
    }
    execution.result = json.dumps(result)
    db.session.commit()
    record_audit(_actor(), 'soar.execution_rolled_back', f'execution/{execution.id}')
    return jsonify(execution.to_dict())


@enterprise_bp.route('/tenants', methods=['GET'])
@jwt_required()
@role_required('admin')
def list_tenants():
    return jsonify([tenant.to_dict() for tenant in Tenant.query.order_by(Tenant.name).all()])


@enterprise_bp.route('/tenants', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_tenant():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    slug = str(data.get('slug', '')).strip().lower()
    if not name or not re.fullmatch(r'[a-z0-9-]{2,80}', slug):
        return jsonify({'error': 'name and a lowercase slug are required'}), 400
    if Tenant.query.filter((Tenant.name == name) | (Tenant.slug == slug)).first():
        return jsonify({'error': 'Tenant name or slug already exists'}), 409
    tenant = Tenant(name=name, slug=slug)
    db.session.add(tenant)
    db.session.commit()
    record_audit(_actor(), 'tenant.created', f'tenant/{tenant.id}')
    return jsonify(tenant.to_dict()), 201


@enterprise_bp.route('/operations/health', methods=['GET'])
@jwt_required()
@role_required('admin')
def operations_health():
    try:
        db.session.execute(text('SELECT 1'))
        ingestion = {
            'queued': SecurityEvent.query.filter_by(status='queued').count(),
            'processing': SecurityEvent.query.filter_by(status='processing').count(),
            'failed': SecurityEvent.query.filter_by(status='failed').count(),
        }
        backup_directory = _sqlite_backup_directory()
        backup_storage = (
            'available'
            if backup_directory and backup_directory.parent.exists() and os.access(backup_directory.parent, os.W_OK)
            else 'not_configured' if backup_directory is None else 'unavailable'
        )
        return jsonify({
            'status': 'healthy' if ingestion['failed'] == 0 else 'degraded',
            'database': 'healthy',
            'ingestion': ingestion,
            'backup_storage': backup_storage,
            'incidents': Incident.query.count(),
            'cases': Case.query.count(),
            'timestamp': datetime.utcnow().isoformat(),
        })
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Operations health check failed")
        return jsonify({
            'status': 'unhealthy',
            'database': 'unhealthy',
            'error': 'Database health check failed',
            'timestamp': datetime.utcnow().isoformat(),
        }), 503


@enterprise_bp.route('/operations/metrics', methods=['GET'])
@jwt_required()
@role_required('admin')
def operations_metrics():
    lines = [
        '# TYPE soar_incidents_total gauge',
        f'soar_incidents_total {Incident.query.count()}',
        '# TYPE soar_cases_total gauge',
        f'soar_cases_total {Case.query.count()}',
        '# TYPE soar_pending_approvals_total gauge',
        f"soar_pending_approvals_total {PlaybookExecution.query.filter_by(status='pending_approval').count()}",
    ]
    return Response('\n'.join(lines) + '\n', mimetype='text/plain')


@enterprise_bp.route('/admin/backups', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_backup():
    backup_directory = _sqlite_backup_directory()
    if backup_directory is None:
        return jsonify({'error': 'Configure managed database backups for non-SQLite deployments'}), 501
    database_path = _sqlite_database_path()
    if database_path is None:
        return jsonify({'error': 'A file-backed SQLite database is required for local backups'}), 501
    if not database_path.exists():
        return jsonify({'error': 'Database file not found'}), 404
    try:
        backup_path = create_sqlite_backup(database_path, backup_directory)
    except Exception:
        current_app.logger.exception("Database backup failed")
        return jsonify({'error': 'Database backup failed'}), 500
    record_audit(_actor(), 'database.backup_created', 'admin/backup', details={'filename': backup_path.name})
    return jsonify({'message': 'Backup created', 'filename': backup_path.name}), 201


def create_sqlite_backup(database_path, backup_directory):
    backup_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_directory, 0o700)
    backup_path = backup_directory / f"{database_path.stem}-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.sqlite"
    temporary_path = backup_path.with_suffix('.sqlite.tmp')
    try:
        with sqlite3.connect(str(database_path), timeout=30) as source:
            with sqlite3.connect(str(temporary_path), timeout=30) as destination:
                os.chmod(temporary_path, 0o600)
                source.backup(destination)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, backup_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return backup_path


@enterprise_bp.route('/admin/backups', methods=['GET'])
@jwt_required()
@role_required('admin')
def list_backups():
    backup_directory = _sqlite_backup_directory()
    database_path = _sqlite_database_path()
    if backup_directory is None or database_path is None:
        return jsonify({'error': 'Configure managed database backups for non-SQLite deployments'}), 501
    if not backup_directory.exists():
        return jsonify([])

    pattern = re.compile(rf'^{re.escape(database_path.stem)}-\d{{20}}\.sqlite$')
    backups = []
    for path in sorted(backup_directory.iterdir(), reverse=True):
        if not pattern.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            continue
        stat = path.stat()
        backups.append({
            'filename': path.name,
            'size_bytes': stat.st_size,
            'created_at': datetime.utcfromtimestamp(stat.st_mtime).isoformat(),
        })
    return jsonify(backups)


@enterprise_bp.route('/admin/backups/<path:filename>', methods=['GET'])
@jwt_required()
@role_required('admin')
def download_backup(filename):
    backup_directory = _sqlite_backup_directory()
    database_path = _sqlite_database_path()
    if backup_directory is None or database_path is None:
        return jsonify({'error': 'Configure managed database backups for non-SQLite deployments'}), 501
    if not re.fullmatch(rf'{re.escape(database_path.stem)}-\d{{20}}\.sqlite', filename):
        return jsonify({'error': 'Backup not found'}), 404
    backup_path = backup_directory / filename
    if backup_path.is_symlink() or not backup_path.is_file():
        return jsonify({'error': 'Backup not found'}), 404
    record_audit(_actor(), 'database.backup_downloaded', 'admin/backup', details={'filename': filename})
    return send_file(backup_path, as_attachment=True, download_name=filename)


def _sqlite_database_path():
    from sqlalchemy.engine.url import make_url

    database_url = make_url(current_app.config['SQLALCHEMY_DATABASE_URI'])
    if database_url.drivername.split('+')[0] != 'sqlite' or not database_url.database:
        return None
    if database_url.database == ':memory:':
        return None
    return Path(database_url.database).expanduser().resolve()


def _sqlite_backup_directory():
    database_path = _sqlite_database_path()
    return database_path.parent / 'backups' if database_path else None