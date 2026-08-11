from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from models import Incident, User, db
from sqlalchemy import func
from datetime import datetime, timedelta
from routes.auth import role_required

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
        return jsonify({"error": "Search failed", "details": str(e)}), 500


@incidents_bp.route("/incidents/<int:incident_id>", methods=["PUT"])
@jwt_required()
@role_required('admin', 'analyst')
def update_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json()

    if 'status' in data:
        incident.status = data['status']

    if 'notes' in data:
        incident.notes = data['notes']

    db.session.commit()

    from app import socketio
    socketio.emit('incident_update', incident.to_dict())
    return jsonify(incident.to_dict())


@incidents_bp.route("/incidents/<int:incident_id>/assign", methods=["PUT"])
@jwt_required()
@role_required('admin', 'analyst')
def assign_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json()

    if 'assigned_to' in data:
        incident.assigned_to = data['assigned_to']

    db.session.commit()

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
