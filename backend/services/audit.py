import json

from flask import has_request_context, request

from models import AuditLog, db


def record_audit(actor, action, resource, outcome='success', details=None):
    entry = AuditLog(
        actor=actor or 'system',
        action=action,
        resource=resource,
        outcome=outcome,
        ip_address=request.remote_addr if has_request_context() else None,
        details=json.dumps(details or {}),
    )
    db.session.add(entry)
    db.session.commit()
    return entry