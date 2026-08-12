import json
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models import db, Asset
from routes.auth import role_required

assets_bp = Blueprint('assets', __name__)


@assets_bp.route('/assets', methods=['GET'])
@jwt_required()
def list_assets():
    assets = Asset.query.order_by(Asset.criticality.desc()).all()
    return jsonify([a.to_dict() for a in assets])


@assets_bp.route('/assets', methods=['POST'])
@jwt_required()
@role_required('admin', 'analyst')
def create_asset():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"error": "name is required"}), 400

    asset = Asset(
        name=data['name'],
        ip_address=data.get('ip_address'),
        hostname=data.get('hostname'),
        asset_type=data.get('asset_type', 'server'),
        os=data.get('os'),
        owner=data.get('owner'),
        criticality=data.get('criticality', 'medium'),
        status=data.get('status', 'active'),
        open_ports=json.dumps(data.get('open_ports', [])),
        tags=json.dumps(data.get('tags', [])),
        notes=data.get('notes', ''),
    )
    db.session.add(asset)
    db.session.commit()
    return jsonify(asset.to_dict()), 201


@assets_bp.route('/assets/<int:asset_id>', methods=['GET'])
@jwt_required()
def get_asset(asset_id):
    return jsonify(Asset.query.get_or_404(asset_id).to_dict())


@assets_bp.route('/assets/<int:asset_id>', methods=['PUT'])
@jwt_required()
@role_required('admin', 'analyst')
def update_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    data = request.get_json() or {}
    for field in ['name', 'ip_address', 'hostname', 'asset_type', 'os', 'owner', 'criticality', 'status', 'notes']:
        if field in data:
            setattr(asset, field, data[field])
    if 'open_ports' in data:
        asset.open_ports = json.dumps(data['open_ports'])
    if 'tags' in data:
        asset.tags = json.dumps(data['tags'])
    asset.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify(asset.to_dict())


@assets_bp.route('/assets/<int:asset_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    db.session.delete(asset)
    db.session.commit()
    return jsonify({"message": "Asset deleted"})


@assets_bp.route('/assets/search', methods=['GET'])
@jwt_required()
def search_assets():
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify({"error": "Query too short"}), 400
    results = Asset.query.filter(
        db.or_(Asset.name.ilike(f'%{q}%'), Asset.ip_address.ilike(f'%{q}%'),
               Asset.hostname.ilike(f'%{q}%'))
    ).all()
    return jsonify([a.to_dict() for a in results])
