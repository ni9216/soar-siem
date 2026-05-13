from flask import Blueprint, jsonify, request
from models import Incident, User, db
from sqlalchemy import func
from datetime import datetime, timedelta

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.route("/incidents", methods=["GET"])
def get_incidents():
    incidents = Incident.query.order_by(Incident.id.desc()).all()
    return jsonify([i.to_dict() for i in incidents])


@incidents_bp.route("/incidents/<int:incident_id>", methods=["PUT"])
def update_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json()

    if 'status' in data:
        incident.status = data['status']

    db.session.commit()
    return jsonify(incident.to_dict())


@incidents_bp.route("/incidents/<int:incident_id>/assign", methods=["PUT"])
def assign_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json()

    if 'assigned_to' in data:
        incident.assigned_to = data['assigned_to']

    db.session.commit()
    return jsonify(incident.to_dict())


@incidents_bp.route("/stats", methods=["GET"])
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


@incidents_bp.route("/users", methods=["GET"])
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'role': u.role
    } for u in users])
