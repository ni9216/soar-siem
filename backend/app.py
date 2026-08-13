from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, decode_token
import json
from datetime import datetime
import subprocess
import socket
import threading
import time
from collections import deque
import os
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import text
from models import db, Incident, User, ThreatFeed, Playbook, Asset, Case
from config import Config

# =========================
# IN-MEMORY ALTERNATIVES (NO EXTERNAL SERVICES NEEDED)
# =========================

class InMemoryElasticsearch:
    def __init__(self):
        self.indices = {}
        self.data = {}

    def ping(self):
        return True

    def index(self, index, document):
        if index not in self.data:
            self.data[index] = []
        self.data[index].append(document)
        return {"_id": str(len(self.data[index])), "result": "created"}

    def search(self, index, query):
        if index not in self.data:
            return {"hits": {"hits": []}}
        # Simple text search
        results = []
        search_term = query.get("query", {}).get("match", {}).get("log", "")
        for doc in self.data[index]:
            if search_term.lower() in str(doc).lower():
                results.append({"_source": doc})
        return {"hits": {"hits": results}}

class InMemoryKafka:
    def __init__(self):
        self.topics = {}
        self.consumers = []

    def send(self, topic, value):
        if topic not in self.topics:
            self.topics[topic] = deque(maxlen=1000)  # Keep last 1000 messages
        self.topics[topic].append(value)
        # Notify consumers
        for consumer in self.consumers:
            if hasattr(consumer, 'callback') and consumer.topic == topic:
                consumer.callback(value)

    def subscribe(self, topic, callback):
        self.consumers.append(type('Consumer', (), {'topic': topic, 'callback': callback})())

class InMemoryRedis:
    def __init__(self):
        self.data = {}

    def set(self, key, value):
        self.data[key] = value

    def get(self, key):
        return self.data.get(key)

    def delete(self, key):
        return self.data.pop(key, None)

# =========================
# OPTIONAL ML (SAFE FALLBACK)
# =========================
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_ENABLED = True
except ImportError:
    ML_ENABLED = False


# =========================
# APP SETUP
# =========================
app = Flask(__name__)
app.config.from_object(Config)
app.static_folder = 'static'

# Restrict CORS to safe origins
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173').split(',')
CORS(app, origins=ALLOWED_ORIGINS)

db.init_app(app)

# Restrict Socket.IO CORS
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode="threading")

jwt = JWTManager(app)


@socketio.on('connect')
def handle_connect(auth):
    token = None
    if isinstance(auth, dict):
        token = auth.get('token')
    if not token:
        token = request.args.get('token')

    if not token:
        print("Socket.IO connection rejected: no token provided")
        return False

    try:
        # This will raise an exception if token is expired
        decoded = decode_token(token)
        username = decoded.get('sub') or decoded.get('identity')
        user = User.query.filter_by(username=username).first()
        if not username or not user:
            print(f"Socket.IO connection rejected: invalid user {username}")
            return False
    except Exception as e:
        print(f"Socket.IO connection rejected: invalid or expired token - {str(e)}")
        return False

    return True

# Initialize in-memory services (no external dependencies!)
es = InMemoryElasticsearch()
kafka_producer = InMemoryKafka()
kafka_consumer = InMemoryKafka()
redis_client = InMemoryRedis()

# All services are now enabled with in-memory implementations
ES_ENABLED = True
KAFKA_ENABLED = True
CONSUMER_ENABLED = True

# Initialize Celery with proper broker configuration
from services.soar_engine import celery
try:
    # Try to use Redis if available, otherwise fall back to in-memory
    celery.conf.update(
        broker_url=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
        result_backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=30 * 60  # 30 minutes hard limit
    )
except Exception as e:
    print(f"Warning: Celery broker configuration failed: {e}")


# =========================
# IMPORT BLUEPRINTS (FIXED)
# =========================
from routes.logs import logs_bp
from routes.incidents import incidents_bp
from routes.scan import scan_bp
from routes.auth import auth_bp
from routes.threats import threats_bp
from routes.soar import soar_bp
from routes.playbooks import playbooks_bp
from routes.twofa import twofa_bp
from routes.assets import assets_bp
from routes.cases import cases_bp
from routes.reports import reports_bp
from routes.intel import intel_bp


# =========================
# REGISTER BLUEPRINTS
# =========================
app.register_blueprint(logs_bp, url_prefix="/api")
app.register_blueprint(incidents_bp, url_prefix="/api")
app.register_blueprint(scan_bp, url_prefix="/api")
app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(threats_bp, url_prefix="/api")
app.register_blueprint(soar_bp, url_prefix="/api")
app.register_blueprint(playbooks_bp, url_prefix="/api")
app.register_blueprint(twofa_bp, url_prefix="/api")
app.register_blueprint(assets_bp, url_prefix="/api")
app.register_blueprint(cases_bp, url_prefix="/api")
app.register_blueprint(reports_bp, url_prefix="/api")
app.register_blueprint(intel_bp, url_prefix="/api")


# =========================
# STATUS ROUTE (TEST SERVER)
# =========================
@app.route("/api/status")
def status():
    return jsonify({
        "status": "OK",
        "message": "Enterprise SIEM Running 🚀"
    })


# =========================
# SOCKET EVENT EMITTER
# =========================
def emit_event(incident):
    socketio.emit("new_incident", {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "details": incident.details,
        "time": incident.time
    })

    socketio.emit("log_stream", {
        "timestamp": incident.time,
        "severity": incident.severity,
        "title": incident.title
    })


# =========================
# SERVE FRONTEND
# =========================
@app.route('/')
@app.route('/<path:path>')
def serve_frontend(path=''):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')


# =========================
# START SERVER
# =========================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Fix outdated incident table schema if the database was created with an older model.
        try:
            with db.engine.connect() as conn:
                result = conn.execute(text("PRAGMA table_info(incident)"))
                columns = [row[1] for row in result.fetchall()]
                if 'status' not in columns:
                    conn.execute(text("ALTER TABLE incident ADD COLUMN status VARCHAR(50) DEFAULT 'open'"))
                if 'assigned_to' not in columns:
                    conn.execute(text("ALTER TABLE incident ADD COLUMN assigned_to INTEGER"))
                if 'notes' not in columns:
                    conn.execute(text("ALTER TABLE incident ADD COLUMN notes TEXT DEFAULT ''"))

                # Migrate user table for new features (2FA, notifications)
                result = conn.execute(text("PRAGMA table_info(user)"))
                user_columns = [row[1] for row in result.fetchall()]
                if 'totp_secret' not in user_columns:
                    conn.execute(text("ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)"))
                if 'totp_enabled' not in user_columns:
                    conn.execute(text("ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN DEFAULT 0"))
                if 'email' not in user_columns:
                    conn.execute(text("ALTER TABLE user ADD COLUMN email VARCHAR(120)"))
                if 'notify_email' not in user_columns:
                    conn.execute(text("ALTER TABLE user ADD COLUMN notify_email BOOLEAN DEFAULT 0"))
                if 'notify_slack' not in user_columns:
                    conn.execute(text("ALTER TABLE user ADD COLUMN notify_slack BOOLEAN DEFAULT 0"))

                conn.commit()
        except Exception as exc:
            print(f"Warning: unable to migrate schema automatically: {exc}")

        # Initialize default admin user
        from models import User
        admin_username = os.getenv('DEFAULT_ADMIN_USERNAME', 'admin')
        admin_password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'Admin@Siem2024!')
        existing_admin = User.query.filter_by(username=admin_username).first()
        if not existing_admin:
            admin = User(username=admin_username, role='admin')
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created.")
        elif not existing_admin.check_password(admin_password):
            existing_admin.set_password(admin_password)
            db.session.commit()
            print("Default admin password updated to match environment settings.")

    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('ENVIRONMENT', 'development') != 'production'
    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=debug,
    )