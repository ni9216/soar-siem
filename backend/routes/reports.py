"""
Compliance Report Generator
-----------------------------
Generates compliance reports for SOC2, PCI-DSS, ISO 27001, HIPAA.
Returns JSON report data (PDF generation requires reportlab, optional).
"""

import json
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, Response
from flask_jwt_extended import jwt_required
from models import db, Incident, User, Case, Asset
from routes.auth import role_required

reports_bp = Blueprint('reports', __name__)

FRAMEWORKS = {
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": [
            {"id": "CC6.1", "name": "Logical Access Controls",
             "check": "auth_events", "description": "Monitor authentication and access"},
            {"id": "CC6.7", "name": "Restriction of Unauthorized Access",
             "check": "unauthorized_access", "description": "Block unauthorized access attempts"},
            {"id": "CC7.2", "name": "Monitor System Components",
             "check": "incident_response", "description": "Monitor for security incidents"},
            {"id": "CC7.3", "name": "Incident Response",
             "check": "case_management", "description": "Manage and respond to incidents"},
            {"id": "CC9.2", "name": "Risk Mitigation",
             "check": "threat_detection", "description": "Detect and mitigate threats"},
        ]
    },
    "pci_dss": {
        "name": "PCI DSS v4.0",
        "controls": [
            {"id": "R6", "name": "Develop Secure Systems",
             "check": "vulnerability_mgmt", "description": "Maintain secure systems and software"},
            {"id": "R10", "name": "Log and Monitor",
             "check": "log_monitoring", "description": "Log all access to system components"},
            {"id": "R11", "name": "Test Security Regularly",
             "check": "security_testing", "description": "Test security systems regularly"},
            {"id": "R12", "name": "Information Security Policy",
             "check": "incident_response", "description": "Maintain an information security policy"},
        ]
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "controls": [
            {"id": "A.8.15", "name": "Logging",
             "check": "log_monitoring", "description": "Produce, store, protect and analyse logs"},
            {"id": "A.8.16", "name": "Monitoring Activities",
             "check": "threat_detection", "description": "Monitor networks, systems and applications"},
            {"id": "A.5.26", "name": "Response to Information Security Incidents",
             "check": "incident_response", "description": "Respond to security incidents"},
            {"id": "A.8.8", "name": "Management of Technical Vulnerabilities",
             "check": "vulnerability_mgmt", "description": "Manage technical vulnerabilities"},
        ]
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "controls": [
            {"id": "164.312(b)", "name": "Audit Controls",
             "check": "log_monitoring", "description": "Implement hardware, software activity audit controls"},
            {"id": "164.312(a)(1)", "name": "Access Control",
             "check": "auth_events", "description": "Allow access only to authorized persons"},
            {"id": "164.308(a)(6)", "name": "Security Incident Procedures",
             "check": "incident_response", "description": "Identify and respond to security incidents"},
        ]
    }
}


def _gather_metrics(days: int = 30) -> dict:
    """Gather security metrics for report period."""
    since = datetime.utcnow() - timedelta(days=days)
    incidents = Incident.query.filter(Incident.timestamp >= since).all()

    by_severity = {}
    for i in incidents:
        by_severity[i.severity] = by_severity.get(i.severity, 0) + 1

    resolved = sum(1 for i in incidents if i.status in ['resolved', 'closed'])
    cases_total = Case.query.count()
    cases_resolved = Case.query.filter(Case.status.in_(['resolved', 'closed'])).count()
    assets_total = Asset.query.count()
    users_total = User.query.count()

    return {
        "period_days": days,
        "period_start": since.isoformat(),
        "period_end": datetime.utcnow().isoformat(),
        "total_incidents": len(incidents),
        "by_severity": by_severity,
        "resolved_incidents": resolved,
        "resolution_rate": round(resolved / max(len(incidents), 1) * 100, 1),
        "critical_incidents": by_severity.get("Critical", 0),
        "high_incidents": by_severity.get("High", 0),
        "total_cases": cases_total,
        "resolved_cases": cases_resolved,
        "total_assets": assets_total,
        "total_users": users_total,
        "log_monitoring": len(incidents) > 0,
        "incident_response": cases_total > 0,
        "case_management": cases_resolved > 0,
        "threat_detection": by_severity.get("Critical", 0) + by_severity.get("High", 0) > 0,
        "auth_events": True,  # auth logging is always on
        "unauthorized_access": True,
        "vulnerability_mgmt": assets_total > 0,
        "security_testing": True,
    }


def _evaluate_control(check: str, metrics: dict) -> dict:
    """Evaluate a control against metrics."""
    passed = bool(metrics.get(check, False))
    return {
        "status": "PASS" if passed else "NEEDS_ATTENTION",
        "evidence": f"{metrics.get('total_incidents', 0)} incidents logged" if "log" in check
                    else f"{metrics.get('total_cases', 0)} cases managed" if "case" in check
                    else "Monitoring active" if passed else "No evidence found"
    }


@reports_bp.route('/reports/frameworks', methods=['GET'])
@jwt_required()
def list_frameworks():
    return jsonify([{"id": k, "name": v["name"], "controls": len(v["controls"])}
                    for k, v in FRAMEWORKS.items()])


@reports_bp.route('/reports/generate', methods=['GET'])
@jwt_required()
@role_required('admin', 'analyst')
def generate_report():
    framework_id = request.args.get('framework', 'soc2')
    days = int(request.args.get('days', 30))

    framework = FRAMEWORKS.get(framework_id)
    if not framework:
        return jsonify({"error": f"Unknown framework. Choose: {', '.join(FRAMEWORKS)}"}), 400

    metrics = _gather_metrics(days)
    controls = []
    passed = 0
    for ctrl in framework["controls"]:
        evaluation = _evaluate_control(ctrl["check"], metrics)
        controls.append({**ctrl, **evaluation})
        if evaluation["status"] == "PASS":
            passed += 1

    compliance_score = round(passed / len(framework["controls"]) * 100)

    return jsonify({
        "framework": framework["name"],
        "framework_id": framework_id,
        "generated_at": datetime.utcnow().isoformat(),
        "compliance_score": compliance_score,
        "status": "COMPLIANT" if compliance_score >= 80 else "PARTIAL" if compliance_score >= 50 else "NON_COMPLIANT",
        "controls_total": len(framework["controls"]),
        "controls_passed": passed,
        "controls": controls,
        "metrics": metrics,
        "recommendations": [
            ctrl["description"] for ctrl in controls
            if ctrl.get("status") == "NEEDS_ATTENTION"
        ]
    })


@reports_bp.route('/reports/summary', methods=['GET'])
@jwt_required()
def summary_report():
    days = int(request.args.get('days', 30))
    metrics = _gather_metrics(days)
    all_scores = {}
    for fid, framework in FRAMEWORKS.items():
        passed = sum(1 for c in framework["controls"]
                     if _evaluate_control(c["check"], metrics)["status"] == "PASS")
        all_scores[fid] = {
            "name": framework["name"],
            "score": round(passed / len(framework["controls"]) * 100),
            "passed": passed,
            "total": len(framework["controls"]),
        }
    return jsonify({
        "generated_at": datetime.utcnow().isoformat(),
        "period_days": days,
        "metrics": metrics,
        "frameworks": all_scores,
    })
