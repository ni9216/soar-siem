import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models import db, Playbook, Incident
from routes.auth import role_required, get_current_user
from services.notifications import notify_all

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
    """Find and execute matching enabled playbooks for an incident."""
    playbooks = Playbook.query.filter(
        Playbook.enabled == True,
        Playbook.trigger_severity.in_([incident.severity, 'Any'])
    ).all()

    for pb in playbooks:
        actions = json.loads(pb.actions) if pb.actions else []
        subject = f"[{incident.severity}] {incident.title}"
        message = (
            f"Incident #{incident.id}\n"
            f"Severity : {incident.severity}\n"
            f"MITRE    : {incident.mitre_attack_id}\n"
            f"Details  : {incident.details}\n"
            f"Playbook : {pb.name}"
        )

        if 'notify_slack' in actions or 'notify_discord' in actions or 'notify_email' in actions:
            notify_all(subject, message, incident.severity)


@playbooks_bp.route('/playbooks', methods=['GET'])
@jwt_required()
def list_playbooks():
    seed_default_playbooks()
    return jsonify([p.to_dict() for p in Playbook.query.all()])


@playbooks_bp.route('/playbooks', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_playbook():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"error": "name is required"}), 400

    if Playbook.query.filter_by(name=data['name']).first():
        return jsonify({"error": "Playbook name already exists"}), 400

    pb = Playbook(
        name=data['name'],
        description=data.get('description', ''),
        trigger_severity=data.get('trigger_severity', 'Critical'),
        actions=json.dumps(data.get('actions', [])),
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
    data = request.get_json()

    if 'name' in data:
        pb.name = data['name']
    if 'description' in data:
        pb.description = data['description']
    if 'trigger_severity' in data:
        pb.trigger_severity = data['trigger_severity']
    if 'actions' in data:
        pb.actions = json.dumps(data['actions'])
    if 'enabled' in data:
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
    data = request.get_json() or {}
    incident_id = data.get('incident_id')
    incident = Incident.query.get_or_404(incident_id) if incident_id else None

    if incident:
        run_playbook_for_incident(incident)
        return jsonify({"message": f"Playbook '{pb.name}' executed for incident #{incident_id}"})

    return jsonify({"message": f"Playbook '{pb.name}' executed"}), 200
