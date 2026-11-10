from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from models import Incident, User, db
from sqlalchemy import func
from datetime import datetime, timedelta
from routes.auth import role_required
from services.audit import record_audit
from services.incident_workflow import append_incident_timeline

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.route("/incidents", methods=["GET"])
@jwt_required()
def get_incidents():
    incidents = Incident.query.order_by(Incident.id.desc()).all()
    return jsonify([i.to_dict() for i in incidents])


@incidents_bp.route("/search", methods=["GET"])
@jwt_required()
def search_incidents():
    """Search incidents by title and details"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return jsonify({"error": "Search query 'q' parameter is required"}), 400
    
    if len(query) < 2:
        return jsonify({"error": "Search query must be at least 2 characters"}), 400
    
    try:
        # Search in both title and details
        incidents = Incident.query.filter(
            (Incident.title.ilike(f'%{query}%')) |
            (Incident.details.ilike(f'%{query}%')) |
            (Incident.mitre_attack_id.ilike(f'%{query}%'))
        ).order_by(Incident.id.desc()).all()
        
        return jsonify([i.to_dict() for i in incidents])
    except Exception as e:
        print(f"Incident search error: {e}")  # Log for debugging
        return jsonify({"error": "Search failed"}), 500


@incidents_bp.route("/incidents/<int:incident_id>", methods=["PUT"])
@jwt_required()
@role_required('admin', 'analyst')
def update_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'A JSON object is required'}), 400

    if 'status' in data:
        status = data['status']
        allowed_statuses = {'open', 'triage', 'investigating', 'escalated', 'contained', 'resolved', 'closed'}
        if status not in allowed_statuses:
            return jsonify({'error': 'Invalid incident status'}), 400
        if incident.status != status:
            old_status = incident.status
            incident.status = status
            incident.closed_at = datetime.utcnow() if status in {'resolved', 'closed'} else None
            append_incident_timeline(
                incident,
                get_jwt_identity(),
                'status_changed',
                {'from': old_status, 'to': status},
            )

    if 'notes' in data:
        if not isinstance(data['notes'], str) or len(data['notes']) > 10000:
            return jsonify({'error': 'Notes must be text no longer than 10000 characters'}), 400
        if incident.notes != data['notes']:
            append_incident_timeline(incident, get_jwt_identity(), 'notes_updated')
        incident.notes = data['notes']

    db.session.commit()
    if 'status' in data or 'notes' in data:
        record_audit(
            get_jwt_identity(),
            'incident.updated',
            f'incident/{incident.id}',
            details={
                **({'status': data['status']} if 'status' in data else {}),
                **({'notes_updated': True} if 'notes' in data else {}),
            },
        )

    from app import socketio
    socketio.emit('incident_update', incident.to_dict())
    return jsonify(incident.to_dict())


@incidents_bp.route("/incidents/<int:incident_id>/assign", methods=["PUT"])
@jwt_required()
@role_required('admin', 'analyst')
def assign_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'assigned_to' not in data:
        return jsonify({'error': 'assigned_to is required'}), 400

    assigned_to = data['assigned_to']
    if assigned_to is not None:
        try:
            assigned_to = int(assigned_to)
        except (TypeError, ValueError):
            return jsonify({'error': 'assigned_to must be a valid analyst ID or null'}), 400
        assignee = User.query.get(assigned_to)
        if assignee is None or assignee.role not in {'admin', 'analyst'}:
            return jsonify({'error': 'Assignee must be an existing analyst or administrator'}), 400

    if incident.assigned_to != assigned_to:
        previous_assignee = incident.assigned_to
        incident.assigned_to = assigned_to
        append_incident_timeline(
            incident,
            get_jwt_identity(),
            'assigned',
            {'from': previous_assignee, 'to': assigned_to},
        )

    db.session.commit()
    record_audit(
        get_jwt_identity(),
        'incident.assigned',
        f'incident/{incident.id}',
        details={'assigned_to': assigned_to},
    )

    from app import socketio
    socketio.emit('incident_update', incident.to_dict())
    return jsonify(incident.to_dict())


@incidents_bp.route("/stats", methods=["GET"])
@jwt_required()
def get_stats():
    # Get severity counts
    severity_counts = db.session.query(
        Incident.severity, func.count(Incident.id)
    ).group_by(Incident.severity).all()

    stats = {}
    for severity, count in severity_counts:
        stats[severity] = count

    # Ensure all severity levels are present
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if severity not in stats:
            stats[severity] = 0

    return jsonify(stats)


@incidents_bp.route("/trends", methods=["GET"])
@jwt_required()
def get_trends():
    # Get incidents from last 24 hours
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_incidents = Incident.query.filter(
        Incident.timestamp >= yesterday
    ).order_by(Incident.timestamp).all()

    # Group by hour
    trends = []
    current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)

    for i in range(24):
        hour_start = current_hour - timedelta(hours=23-i)
        hour_end = hour_start + timedelta(hours=1)

        hour_incidents = [inc for inc in recent_incidents
                         if hour_start <= inc.timestamp <= hour_end]

        severity_value = 0
        for inc in hour_incidents:
            if inc.severity == 'Critical':
                severity_value += 4
            elif inc.severity == 'High':
                severity_value += 3
            elif inc.severity == 'Medium':
                severity_value += 2
            elif inc.severity == 'Low':
                severity_value += 1

        trends.append({
            'time': hour_start.strftime('%H:00'),
            'value': severity_value
        })

    return jsonify(trends)
