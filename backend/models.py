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
    alert_group_id = db.Column(db.Integer, db.ForeignKey('alert_group.id'), nullable=True)
    notes = db.Column(db.Text, default='')
    sla_due_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)
    timeline = db.Column(db.Text, default='[]', nullable=False)

    def to_dict(self):
        import json
        from services.incident_workflow import incident_sla_deadline

        sla_due_at = self.sla_due_at or incident_sla_deadline(self.severity, self.timestamp)
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
            "alert_group_id": self.alert_group_id,
            "notes": self.notes,
            "sla_due_at": sla_due_at.isoformat() if sla_due_at else None,
            "sla_breached": bool(
                sla_due_at
                and sla_due_at < datetime.utcnow()
                and self.status not in {'resolved', 'closed'}
            ),
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "timeline": json.loads(self.timeline or '[]'),
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


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    hostname = db.Column(db.String(100), nullable=True)
    asset_type = db.Column(db.String(50), default='server')   # server, workstation, network, cloud
    os = db.Column(db.String(100), nullable=True)
    owner = db.Column(db.String(100), nullable=True)
    criticality = db.Column(db.String(20), default='medium')   # low, medium, high, critical
    status = db.Column(db.String(20), default='active')
    last_seen = db.Column(db.DateTime, nullable=True)
    open_ports = db.Column(db.Text, default='[]')
    tags = db.Column(db.Text, default='[]')
    notes = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json
        return {
            "id": self.id, "name": self.name, "ip_address": self.ip_address,
            "hostname": self.hostname, "asset_type": self.asset_type,
            "os": self.os, "owner": self.owner, "criticality": self.criticality,
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "open_ports": json.loads(self.open_ports) if self.open_ports else [],
            "tags": json.loads(self.tags) if self.tags else [],
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    severity = db.Column(db.String(20), default='Medium')
    status = db.Column(db.String(30), default='open')  # open, investigating, escalated, resolved, closed
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    incident_ids = db.Column(db.Text, default='[]')   # JSON list of related incident IDs
    asset_ids = db.Column(db.Text, default='[]')      # JSON list of related asset IDs
    timeline = db.Column(db.Text, default='[]')       # JSON list of timeline events
    tags = db.Column(db.Text, default='[]')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        import json
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "severity": self.severity, "status": self.status,
            "assigned_to": self.assigned_to,
            "incident_ids": json.loads(self.incident_ids) if self.incident_ids else [],
            "asset_ids": json.loads(self.asset_ids) if self.asset_ids else [],
            "timeline": json.loads(self.timeline) if self.timeline else [],
            "tags": json.loads(self.tags) if self.tags else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }


class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    slug = db.Column(db.String(80), unique=True, nullable=False)
    status = db.Column(db.String(20), default='active', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }


class SecuritySetting(db.Model):
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.String(500), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(80), nullable=False, default='system')
    action = db.Column(db.String(120), nullable=False)
    resource = db.Column(db.String(200), nullable=False)
    outcome = db.Column(db.String(20), nullable=False, default='success')
    ip_address = db.Column(db.String(45))
    details = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "ip_address": self.ip_address,
            "details": json.loads(self.details or '{}'),
            "created_at": self.created_at.isoformat(),
        }


class AlertGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grouping_key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    mitre_attack_id = db.Column(db.String(50))
    status = db.Column(db.String(30), default='open', nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    incident_count = db.Column(db.Integer, default=0, nullable=False)
    suppressed_count = db.Column(db.Integer, default=0, nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "mitre_attack_id": self.mitre_attack_id,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "incident_count": self.incident_count,
            "suppressed_count": self.suppressed_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


class LogSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=True, index=True)
    name = db.Column(db.String(120), nullable=False)
    connector_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='inactive', nullable=False)
    configuration = db.Column(db.Text, default='{}')
    last_sync = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "name": self.name,
            "connector_type": self.connector_type,
            "status": self.status,
            "configuration": json.loads(self.configuration or '{}'),
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "created_at": self.created_at.isoformat(),
        }


class DetectionRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default='')
    pattern = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), default='Medium', nullable=False)
    mitre_attack_id = db.Column(db.String(50))
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    version = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "severity": self.severity,
            "mitre_attack_id": self.mitre_attack_id,
            "enabled": self.enabled,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class PlaybookExecution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False, index=True)
    playbook = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(30), default='pending', nullable=False)
    initiated_by = db.Column(db.String(80), nullable=False)
    requires_approval = db.Column(db.Boolean, default=False, nullable=False)
    actions = db.Column(db.Text, default='[]')
    result = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.String(80))
    completed_at = db.Column(db.DateTime)

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "playbook": self.playbook,
            "status": self.status,
            "initiated_by": self.initiated_by,
            "requires_approval": self.requires_approval,
            "actions": json.loads(self.actions or '[]'),
            "result": json.loads(self.result or '{}'),
            "created_at": self.created_at.isoformat(),
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class IngestionSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    source_type = db.Column(db.String(50), nullable=False)
    api_key_hash = db.Column(db.String(256), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=True, index=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    rate_limit_per_minute = db.Column(db.Integer, default=600, nullable=False)
    last_seen = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "source_type": self.source_type,
            "tenant_id": self.tenant_id,
            "enabled": self.enabled,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat(),
        }


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    source_id = db.Column(db.Integer, db.ForeignKey('ingestion_source.id'), nullable=False, index=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=True, index=True)
    event_type = db.Column(db.String(100), nullable=False)
    occurred_at = db.Column(db.DateTime, nullable=False, index=True)
    host = db.Column(db.String(255))
    username = db.Column(db.String(255))
    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    message = db.Column(db.Text, nullable=False)
    normalized_event = db.Column(db.Text, nullable=False)
    raw_event = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), default='queued', nullable=False, index=True)
    processing_error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    processed_at = db.Column(db.DateTime)

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "event_id": self.event_id,
            "source_id": self.source_id,
            "tenant_id": self.tenant_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at.isoformat(),
            "host": self.host,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "message": self.message,
            "normalized_event": json.loads(self.normalized_event),
            "status": self.status,
            "processing_error": self.processing_error,
            "created_at": self.created_at.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
        }
