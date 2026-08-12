import json
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Case
from routes.auth import role_required, get_current_user

cases_bp = Blueprint('cases', __name__)


def _add_timeline(case, action, user):
    tl = json.loads(case.timeline) if case.timeline else []
    tl.append({"ts": datetime.utcnow().isoformat(), "action": action, "by": user})
    case.timeline = json.dumps(tl)


@cases_bp.route('/cases', methods=['GET'])
@jwt_required()
def list_cases():
    status = request.args.get('status')
    q = Case.query
    if status:
        q = q.filter_by(status=status)
    return jsonify([c.to_dict() for c in q.order_by(Case.created_at.desc()).all()])


@cases_bp.route('/cases', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def create_case():
    data = request.get_json()
    if not data or not data.get('title'):
        return jsonify({"error": "title is required"}), 400

    user = get_current_user()
    case = Case(
        title=data['title'],
        description=data.get('description', ''),
        severity=data.get('severity', 'Medium'),
        status='open',
        incident_ids=json.dumps(data.get('incident_ids', [])),
        asset_ids=json.dumps(data.get('asset_ids', [])),
        tags=json.dumps(data.get('tags', [])),
    )
    db.session.add(case)
    db.session.flush()
    _add_timeline(case, "Case created", user.username if user else "system")
    db.session.commit()
    return jsonify(case.to_dict()), 201


@cases_bp.route('/cases/<int:case_id>', methods=['GET'])
@jwt_required()
def get_case(case_id):
    return jsonify(Case.query.get_or_404(case_id).to_dict())


@cases_bp.route('/cases/<int:case_id>', methods=['PUT'])
@jwt_required()
@role_required('admin', 'analyst')
def update_case(case_id):
    case = Case.query.get_or_404(case_id)
    data = request.get_json() or {}
    user = get_current_user()

    old_status = case.status
    for field in ['title', 'description', 'severity', 'status', 'assigned_to']:
        if field in data:
            setattr(case, field, data[field])
    for jfield in ['incident_ids', 'asset_ids', 'tags']:
        if jfield in data:
            setattr(case, jfield, json.dumps(data[jfield]))

    if data.get('status') != old_status:
        _add_timeline(case, f"Status changed: {old_status} → {data['status']}", user.username if user else "system")
        if data.get('status') in ['resolved', 'closed']:
            case.closed_at = datetime.utcnow()

    if 'note' in data:
        _add_timeline(case, f"Note: {data['note']}", user.username if user else "system")

    case.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(case.to_dict())


@cases_bp.route('/cases/<int:case_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_case(case_id):
    case = Case.query.get_or_404(case_id)
    db.session.delete(case)
    db.session.commit()
    return jsonify({"message": "Case deleted"})


@cases_bp.route('/cases/stats', methods=['GET'])
@jwt_required()
def case_stats():
    return jsonify({
        "total": Case.query.count(),
        "open": Case.query.filter_by(status='open').count(),
        "investigating": Case.query.filter_by(status='investigating').count(),
        "resolved": Case.query.filter_by(status='resolved').count(),
        "closed": Case.query.filter_by(status='closed').count(),
    })
