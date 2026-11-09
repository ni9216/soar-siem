import json
from datetime import datetime, timedelta


SLA_HOURS = {
    'Critical': 1,
    'High': 4,
    'Medium': 24,
    'Low': 72,
}


def incident_sla_deadline(severity, created_at=None):
    hours = SLA_HOURS.get(severity)
    if hours is None:
        return None
    return (created_at or datetime.utcnow()) + timedelta(hours=hours)


def append_incident_timeline(incident, actor, action, details=None):
    entries = json.loads(incident.timeline or '[]')
    entries.append({
        'at': datetime.utcnow().isoformat(),
        'actor': actor,
        'action': action,
        'details': details or {},
    })
    incident.timeline = json.dumps(entries)
