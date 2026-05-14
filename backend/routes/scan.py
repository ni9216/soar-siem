from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/scan", methods=["POST"])
@jwt_required()
def scan_target():

    data = request.get_json()

    if not data or "target" not in data:
        return jsonify({"error": "target field required"}), 400

    target = data.get("target")

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
            "error": str(e)
        }), 500