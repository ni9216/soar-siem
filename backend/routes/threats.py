from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required
from models import ThreatFeed
import requests

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/threats", methods=["GET"])
@jwt_required()
def get_threats():
    threats = ThreatFeed.query.order_by(ThreatFeed.timestamp.desc()).all()
    return jsonify([{
        "id": t.id,
        "indicator": t.indicator,
        "type": t.type,
        "severity": t.severity,
        "source": t.source,
        "timestamp": t.timestamp.isoformat(),
        "description": getattr(t, 'description', '')
    } for t in threats])


@threats_bp.route("/threats/abuseipdb", methods=["GET"])
@jwt_required()
def lookup_abuseipdb():
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({"error": "Query parameter 'ip' is required."}), 400

    api_key = current_app.config.get('ABUSEIPDB_API_KEY', '')
    abuse_url = current_app.config.get('ABUSEIPDB_URL')

    if not api_key:
        return jsonify({
            "ip": ip,
            "source": "AbuseIPDB demo",
            "abuse_confidence_score": 16,
            "abuse_percentage": 40,
            "country": "US",
            "report_count": 18,
            "message": "Demo lookup because ABUSEIPDB_API_KEY is not configured. Set the key to enable live queries."
        })

    try:
        response = requests.get(abuse_url.format(ip=ip), headers={
            'Accept': 'application/json',
            'Key': api_key
        }, timeout=10)
        response.raise_for_status()
        data = response.json().get('data', {})
        return jsonify({
            "ip": ip,
            "source": "AbuseIPDB",
            "abuse_confidence_score": data.get('abuseConfidenceScore'),
            "abuse_percentage": data.get('abuseConfidencePercentage'),
            "country": data.get('countryCode'),
            "report_count": data.get('totalReports'),
            "last_reported": data.get('lastReportedAt'),
            "domain": data.get('domain'),
            "isp": data.get('isp'),
            "hostnames": data.get('hostnames'),
            "raw_data": data,
        })
    except requests.RequestException as exc:
        return jsonify({
            "error": "Failed to query AbuseIPDB.",
            "details": str(exc)
        }), 502
