from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models import Incident, db
from routes.auth import role_required
from services.soar_engine import auto_response

soar_bp = Blueprint("soar", __name__)

PLAYBOOK_STATUS = {
    "containment": "investigating",
    "investigation": "investigating",
    "escalation": "escalated",
}


@soar_bp.route("/soar/run", methods=["POST"])
@jwt_required()
@role_required('admin', 'analyst')
def run_playbook():
    data = request.get_json() or {}
    incident_id = data.get('incident_id')
    playbook = (data.get('playbook') or 'investigation').lower()

    if not incident_id:
        return jsonify({"error": "incident_id is required"}), 400

    incident = Incident.query.get_or_404(incident_id)
    incident.status = PLAYBOOK_STATUS.get(playbook, 'investigating')
    incident.notes = (incident.notes or "") + f"\n[SOAR] {playbook.title()} playbook triggered."
    db.session.commit()

    try:
        auto_response.delay(incident.id, incident.severity, {"details": incident.details or incident.title})
        action = "scheduled"
    except Exception:
        auto_response.apply(args=(incident.id, incident.severity, {"details": incident.details or incident.title}))
        action = "executed synchronously"

    from app import socketio
    socketio.emit('incident_update', incident.to_dict())

    return jsonify({
        "message": f"SOAR playbook '{playbook}' {action} for incident {incident.id}.",
        "incident": incident.to_dict(),
    })
