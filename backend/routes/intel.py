from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from services.correlation_engine import check_attack_chains, get_ip_timeline, get_all_suspicious_ips
from services.threat_feed_auto import check_indicator, scan_log_for_iocs, get_blocklist_stats
from services.behavioral_baseline import get_user_baseline, get_all_baselines, analyze_deviation
from routes.auth import role_required

intel_bp = Blueprint('intel', __name__)


# ── Correlation ───────────────────────────────────────────────────────────────

@intel_bp.route('/intel/suspicious-ips', methods=['GET'])
@jwt_required()
def suspicious_ips():
    return jsonify(get_all_suspicious_ips())


@intel_bp.route('/intel/ip-timeline', methods=['GET'])
@jwt_required()
def ip_timeline():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    return jsonify(get_ip_timeline(ip))


# ── Threat Feed ───────────────────────────────────────────────────────────────

@intel_bp.route('/intel/check', methods=['GET'])
@jwt_required()
def check_ioc():
    indicator = request.args.get('indicator', '').strip()
    if not indicator:
        return jsonify({"error": "indicator parameter required"}), 400
    return jsonify(check_indicator(indicator))


@intel_bp.route('/intel/blocklist-stats', methods=['GET'])
@jwt_required()
def blocklist_stats():
    return jsonify(get_blocklist_stats())


# ── Behavioral Baseline ───────────────────────────────────────────────────────

@intel_bp.route('/intel/baselines', methods=['GET'])
@jwt_required()
@role_required('admin')
def all_baselines():
    return jsonify(get_all_baselines())


@intel_bp.route('/intel/baseline/<username>', methods=['GET'])
@jwt_required()
def user_baseline(username):
    return jsonify(get_user_baseline(username))


@intel_bp.route('/intel/deviation', methods=['POST'])
@jwt_required()
def check_deviation():
    data = request.get_json() or {}
    user = data.get('user')
    ip = data.get('ip')
    if not user:
        return jsonify({"error": "user is required"}), 400
    return jsonify(analyze_deviation(user, ip))
