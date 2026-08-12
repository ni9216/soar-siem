from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='analyst')
    # 2FA fields
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    # Notification preferences
    email = db.Column(db.String(120), nullable=True)
    notify_email = db.Column(db.Boolean, default=False)
    notify_slack = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_token(self):
        return create_access_token(identity=self.username)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    severity = db.Column(db.String(50))
    details = db.Column(db.Text)
    time = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    mitre_attack_id = db.Column(db.String(50))
    status = db.Column(db.String(50), default='open')
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    notes = db.Column(db.Text, default='')

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "details": self.details,
            "time": self.time,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "mitre_attack_id": self.mitre_attack_id,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "notes": self.notes
        }


class ThreatFeed(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(200), unique=True)
    type = db.Column(db.String(50))
    severity = db.Column(db.String(50))
    source = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Playbook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, default='')
    trigger_severity = db.Column(db.String(50), default='Critical')  # Critical, High, Medium, Low, Any
    actions = db.Column(db.Text, default='[]')  # JSON list of actions
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "trigger_severity": self.trigger_severity,
            "actions": json.loads(self.actions) if self.actions else [],
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
