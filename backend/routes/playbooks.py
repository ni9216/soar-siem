import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
from models import db, Playbook, Incident
from routes.auth import role_required
from services.playbook_safety import create_approved_execution, validate_actions
from services.audit import record_audit

playbooks_bp = Blueprint('playbooks', __name__)

DEFAULT_PLAYBOOKS = [
    {
        "name": "Critical Alert",
        "description": "Notify all channels immediately for critical incidents",
        "trigger_severity": "Critical",
        "actions": ["notify_email", "notify_slack", "notify_discord", "escalate"]
    },
    {
        "name": "High Alert",
        "description": "Send Slack/Discord alert for high severity incidents",
        "trigger_severity": "High",
        "actions": ["notify_slack", "notify_discord"]
    },
    {
        "name": "Medium Alert",
        "description": "Log and send Discord notification for medium incidents",
        "trigger_severity": "Medium",
        "actions": ["notify_discord"]
    },
]


def seed_default_playbooks():
    """Create default playbooks if none exist."""
    if Playbook.query.count() == 0:
        for p in DEFAULT_PLAYBOOKS:
            pb = Playbook(
                name=p['name'],
                description=p['description'],
                trigger_severity=p['trigger_severity'],
                actions=json.dumps(p['actions'])
            )
            db.session.add(pb)
        db.session.commit()


def run_playbook_for_incident(incident: Incident):
    """Queue matching playbooks for administrator approval without running actions."""
    playbooks = Playbook.query.filter(
        Playbook.enabled == True,
        Playbook.trigger_severity.in_([incident.severity, 'Any'])
    ).all()

    for pb in playbooks:
        actions, error = validate_actions(json.loads(pb.actions or '[]'))
        if error:
            raise ValueError(f"Playbook '{pb.name}' contains unsupported actions: {error}")
        create_approved_execution(incident, pb.name, 'system', actions)


@playbooks_bp.route('/playbooks', methods=['GET'])
@jwt_required()
def list_playbooks():
    seed_default_playbooks()
    return jsonify([p.to_dict() for p in Playbook.query.all()])


@playbooks_bp.route('/playbooks', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_playbook():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data.get('name'):
        return jsonify({"error": "name is required"}), 400
    if not isinstance(data['name'], str) or len(data['name']) > 120:
        return jsonify({"error": "name must be text no longer than 120 characters"}), 400
    actions, error = validate_actions(data.get('actions', []))
    if error:
        return jsonify({"error": error}), 400
    trigger_severity = data.get('trigger_severity', 'Critical')
    if not isinstance(trigger_severity, str) or trigger_severity not in {'Critical', 'High', 'Medium', 'Low', 'Any'}:
        return jsonify({"error": "Invalid trigger_severity"}), 400
    if 'enabled' in data and not isinstance(data['enabled'], bool):
        return jsonify({"error": "enabled must be a boolean"}), 400

    if Playbook.query.filter_by(name=data['name']).first():
        return jsonify({"error": "Playbook name already exists"}), 400

    pb = Playbook(
        name=data['name'],
        description=data.get('description', ''),
        trigger_severity=trigger_severity,
        actions=json.dumps(actions),
        enabled=data.get('enabled', True)
    )
    db.session.add(pb)
    db.session.commit()
    return jsonify(pb.to_dict()), 201


@playbooks_bp.route('/playbooks/<int:pb_id>', methods=['PUT'])
@jwt_required()
@role_required('admin')
def update_playbook(pb_id):
    pb = Playbook.query.get_or_404(pb_id)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    if 'name' in data:
        if not isinstance(data['name'], str) or not data['name'].strip() or len(data['name']) > 120:
            return jsonify({"error": "name must be text no longer than 120 characters"}), 400
        pb.name = data['name']
    if 'description' in data:
        pb.description = data['description']
    if 'trigger_severity' in data:
        if not isinstance(data['trigger_severity'], str) or data['trigger_severity'] not in {'Critical', 'High', 'Medium', 'Low', 'Any'}:
            return jsonify({"error": "Invalid trigger_severity"}), 400
        pb.trigger_severity = data['trigger_severity']
    if 'actions' in data:
        actions, error = validate_actions(data['actions'])
        if error:
            return jsonify({"error": error}), 400
        pb.actions = json.dumps(actions)
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return jsonify({"error": "enabled must be a boolean"}), 400
        pb.enabled = data['enabled']

    db.session.commit()
    return jsonify(pb.to_dict())


@playbooks_bp.route('/playbooks/<int:pb_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_playbook(pb_id):
    pb = Playbook.query.get_or_404(pb_id)
    db.session.delete(pb)
    db.session.commit()
    return jsonify({"message": "Playbook deleted"})


@playbooks_bp.route('/playbooks/<int:pb_id>/run', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def run_playbook(pb_id):
    pb = Playbook.query.get_or_404(pb_id)
    if not pb.enabled:
        return jsonify({"error": "Disabled playbooks cannot be run"}), 409
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400
    incident_id = data.get('incident_id')
    if not isinstance(incident_id, int) or incident_id <= 0:
        return jsonify({"error": "incident_id is required"}), 400
    incident = Incident.query.get_or_404(incident_id)
    dry_run = data.get('dry_run', False)
    if not isinstance(dry_run, bool):
        return jsonify({"error": "dry_run must be a boolean"}), 400

    try:
        actions = json.loads(pb.actions or '[]')
        execution = create_approved_execution(
            incident,
            pb.name,
            get_jwt_identity(),
            actions,
            dry_run=dry_run,
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    record_audit(
        get_jwt_identity(),
        'soar.execution_previewed' if dry_run else 'soar.execution_requested',
        f'execution/{execution.id}',
        details={'playbook_id': pb.id, 'requires_approval': not dry_run},
    )
    return jsonify({
        "message": (
            f"Dry run completed for '{pb.name}'; no actions were performed."
            if dry_run else
            f"Playbook '{pb.name}' is awaiting administrator approval."
        ),
        "execution": execution.to_dict(),
    }), 200 if dry_run else 202
