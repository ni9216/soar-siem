from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from models import ThreatFeed

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/threats", methods=["GET"])
@jwt_required()
def get_threats():
    threats = ThreatFeed.query.all()
    return jsonify([{
        "id": t.id,
        "indicator": t.indicator,
        "type": t.type,
        "severity": t.severity,
        "source": t.source,
        "timestamp": t.timestamp.isoformat()
    } for t in threats])