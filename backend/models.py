from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

# shared database object for the application

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='analyst')  # e.g., 'admin', 'analyst', 'operator'
    
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
    mitre_attack_id = db.Column(db.String(50))  # MITRE ATT&CK mapping
    status = db.Column(db.String(50), default='open')  # open, investigating, resolved, closed
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
    type = db.Column(db.String(50))  # e.g., 'IP', 'Domain'
    severity = db.Column(db.String(50))
    source = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
