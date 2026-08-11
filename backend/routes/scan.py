from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import re
import ipaddress

scan_bp = Blueprint("scan", __name__)

def is_valid_target(target):
    """
    Validate that the target is a valid IP address or hostname
    """
    target = target.strip()
    
    # Check if it's a valid IPv4 address
    try:
        ipaddress.IPv4Address(target)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid hostname (basic validation)
    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if re.match(hostname_pattern, target):
        return True
    
    # Reject localhost to prevent scanning your own system in certain contexts
    if target.lower() in ['localhost', '127.0.0.1', '0.0.0.0', '255.255.255.255']:
        return False
    
    return False

@scan_bp.route("/scan", methods=["POST"])
@jwt_required()
def scan_target():

    data = request.get_json()

    if not data or "target" not in data:
        return jsonify({"error": "target field required"}), 400

    target = data.get("target")
    
    # Validate target
    if not target or not isinstance(target, str):
        return jsonify({"error": "Invalid target format"}), 400
    
    if not is_valid_target(target):
        return jsonify({"error": "Invalid target IP address or hostname"}), 400

    try:
        import nmap
    except ImportError:
        return jsonify({"error": "nmap python package is not installed"}), 500

    scanner = nmap.PortScanner()

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

    except Exception as e:
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500