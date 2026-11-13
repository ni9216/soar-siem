from flask import Blueprint, current_app, request, jsonify
from flask_jwt_extended import jwt_required
import ipaddress

from models import Asset
from routes.auth import role_required

scan_bp = Blueprint("scan", __name__)

def is_valid_target(target):
    try:
        address = ipaddress.IPv4Address(target)
    except ValueError:
        return False

    if address.is_loopback or address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        return False
    return True

@scan_bp.route("/scan", methods=["POST"])
@jwt_required()
@role_required("admin", "analyst")
def scan_target():
    data = request.get_json()

    if not data or "target" not in data:
        return jsonify({"error": "target field required"}), 400

    target = data.get("target")
    
    # Validate target
    if not target or not isinstance(target, str):
        return jsonify({"error": "Invalid target format"}), 400

    target = target.strip()
    if not is_valid_target(target):
        return jsonify({"error": "Enter a valid, non-loopback IPv4 address."}), 400

    asset = Asset.query.filter_by(ip_address=target, status="active").first()
    if not asset:
        return jsonify({"error": "Scans are restricted to active, registered assets."}), 403

    try:
        import nmap
    except ImportError:
        current_app.logger.exception("Nmap Python package is unavailable")
        return jsonify({"error": "Scanning is unavailable: Nmap is not installed on the server."}), 503

    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        current_app.logger.exception("Nmap executable is unavailable")
        return jsonify({"error": "Scanning is unavailable: Nmap is not installed on the server."}), 503

    try:
        scanner.scan(target, arguments='-sV -p 1-1024')

        results = []

        for host in scanner.all_hosts():

            for proto in scanner[host].all_protocols():

                ports = scanner[host][proto].keys()

                for port in ports:

                    results.append({
                        "host": host,
                        "port": port,
                        "state": scanner[host][proto][port]["state"]
                    })

        return jsonify(results)

    except ImportError:
        current_app.logger.exception("Nmap Python package is unavailable")
        return jsonify({"error": "Scanning is unavailable: Nmap is not installed on the server."}), 503
    except Exception:
        current_app.logger.exception("Nmap scan failed for registered asset %s", asset.id)
        return jsonify({"error": "Scan failed. Check that the registered asset is reachable."}), 502