import pyotp
import qrcode
import io
import base64
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, create_access_token
from models import db, User
from routes.auth import get_current_user

twofa_bp = Blueprint('twofa', __name__)


@twofa_bp.route('/2fa/setup', methods=['POST'])
@jwt_required()
def setup_2fa():
    """Generate a TOTP secret and return a QR code for the authenticator app."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # Generate new secret
    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.session.commit()

    # Build otpauth URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="SOAR SIEM")

    # Generate QR code as base64 image
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return jsonify({
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_b64}",
        "message": "Scan the QR code with Google Authenticator or Authy, then verify."
    })


@twofa_bp.route('/2fa/verify', methods=['POST'])
@jwt_required()
def verify_2fa():
    """Verify a TOTP code and enable 2FA on the account."""
    user = get_current_user()
    if not user or not user.totp_secret:
        return jsonify({"error": "Run /api/2fa/setup first"}), 400

    data = request.get_json() or {}
    code = str(data.get('code', '')).strip()
    if not code:
        return jsonify({"error": "code is required"}), 400

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code):
        return jsonify({"error": "Invalid code"}), 401

    user.totp_enabled = True
    db.session.commit()
    return jsonify({"message": "2FA enabled successfully"})


@twofa_bp.route('/2fa/disable', methods=['POST'])
@jwt_required()
def disable_2fa():
    """Disable 2FA for the current user."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    code = str(data.get('code', '')).strip()

    if user.totp_enabled:
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(code):
            return jsonify({"error": "Invalid 2FA code"}), 401

    user.totp_enabled = False
    user.totp_secret = None
    db.session.commit()
    return jsonify({"message": "2FA disabled"})


@twofa_bp.route('/2fa/status', methods=['GET'])
@jwt_required()
def twofa_status():
    """Check if 2FA is enabled for the current user."""
    user = get_current_user()
    return jsonify({
        "totp_enabled": user.totp_enabled if user else False
    })
