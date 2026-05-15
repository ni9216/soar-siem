from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from models import db, User

auth_bp = Blueprint("auth", __name__)


def get_current_user():
    username = get_jwt_identity()
    return User.query.filter_by(username=username).first()


def role_required(*allowed_roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            user = get_current_user()
            if not user or user.role not in allowed_roles:
                return jsonify({"error": "Unauthorized"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        token = user.generate_token()
        return jsonify({
            "token": token,
            "role": user.role
        })

    return jsonify({
        "error": "Invalid credentials"
    }), 401


@auth_bp.route("/register", methods=["POST"])
@jwt_required()
def register():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "analyst")

    if role not in ['admin', 'analyst', 'viewer']:
        return jsonify({"error": "Invalid role specified"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created"}), 201


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def profile():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "username": current_user.username,
        "role": current_user.role
    })


@auth_bp.route("/users", methods=["GET"])
@jwt_required()
@role_required('admin')
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'role': u.role
    } for u in users])


@auth_bp.route("/users", methods=["POST"])
@jwt_required()
@role_required('admin')
def create_user():
    current_user = get_current_user()
    if current_user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "analyst")

    if role not in ['admin', 'analyst', 'viewer']:
        return jsonify({"error": "Invalid role specified"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "id": new_user.id,
        "username": new_user.username,
        "role": new_user.role
    }), 201


@auth_bp.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
@role_required('admin')
def update_user(user_id):
    current_user = get_current_user()
    if current_user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if 'username' in data:
        if User.query.filter_by(username=data['username']).filter(User.id != user_id).first():
            return jsonify({"error": "Username already exists"}), 400
        user.username = data['username']

    if 'password' in data and data['password']:
        user.set_password(data['password'])

    if 'role' in data:
        if data['role'] not in ['admin', 'analyst', 'viewer']:
            return jsonify({"error": "Invalid role specified"}), 400
        user.role = data['role']

    db.session.commit()

    return jsonify({
        "id": user.id,
        "username": user.username,
        "role": user.role
    })


@auth_bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
@role_required('admin')
def delete_user(user_id):
    current_user = get_current_user()
    if current_user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.get_or_404(user_id)
    
    # Prevent deleting self
    if user.id == current_user.id:
        return jsonify({"error": "Cannot delete your own account"}), 400

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User deleted"}), 200
