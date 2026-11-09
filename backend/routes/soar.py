from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
from models import Incident
from routes.auth import role_required
from services.audit import record_audit
from services.playbook_safety import WORKFLOW_ACTIONS, create_approved_execution

soar_bp = Blueprint("soar", __name__)


@soar_bp.route("/soar/run", methods=["POST"])
@jwt_required()
@role_required('admin', 'analyst')
def run_playbook():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400
    incident_id = data.get('incident_id')
    playbook = data.get('playbook', 'investigation')

    if not isinstance(incident_id, int) or incident_id <= 0:
        return jsonify({"error": "incident_id is required"}), 400
    if not isinstance(playbook, str) or playbook.lower() not in WORKFLOW_ACTIONS:
        return jsonify({"error": "Unsupported playbook"}), 400
    dry_run = data.get('dry_run', False)
    if not isinstance(dry_run, bool):
        return jsonify({"error": "dry_run must be a boolean"}), 400

    incident = Incident.query.get_or_404(incident_id)
    execution = create_approved_execution(
        incident,
        playbook.lower(),
        get_jwt_identity(),
        [playbook.lower()],
        dry_run=dry_run,
    )
    record_audit(
        get_jwt_identity(),
        'soar.execution_previewed' if dry_run else 'soar.execution_requested',
        f'execution/{execution.id}',
        details={'requires_approval': not dry_run},
    )

    return jsonify({
        "message": (
            f"Dry run completed for '{playbook.lower()}'; no actions were performed."
            if dry_run else
            f"SOAR playbook '{playbook.lower()}' is awaiting administrator approval."
        ),
        "incident": incident.to_dict(),
        "execution": execution.to_dict(),
    }), 200 if dry_run else 202
