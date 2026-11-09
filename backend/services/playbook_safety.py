import json

from models import PlaybookExecution, db


WORKFLOW_ACTIONS = {'containment', 'investigation', 'escalation'}
NOTIFICATION_ACTIONS = {'notify_email', 'notify_slack', 'notify_discord', 'escalate'}
ALLOWED_ACTIONS = WORKFLOW_ACTIONS | NOTIFICATION_ACTIONS


def validate_actions(actions):
    if not isinstance(actions, list) or not actions:
        return None, 'actions must be a non-empty list'
    if any(not isinstance(action, str) or action not in ALLOWED_ACTIONS for action in actions):
        return None, 'actions contains an unsupported action'
    return list(dict.fromkeys(actions)), None


def create_approved_execution(incident, playbook, actor, actions, dry_run=False):
    validated_actions, error = validate_actions(actions)
    if error:
        raise ValueError(error)

    execution = PlaybookExecution(
        incident_id=incident.id,
        playbook=playbook,
        initiated_by=actor,
        requires_approval=not dry_run,
        status='dry_run' if dry_run else 'pending_approval',
        actions=json.dumps(validated_actions),
        result=json.dumps({
            'execution_mode': 'dry_run' if dry_run else 'approval_required',
            'planned_actions': validated_actions,
            'external_actions_performed': False,
        }),
    )
    db.session.add(execution)
    db.session.commit()
    return execution
