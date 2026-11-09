import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite://'

from flask_jwt_extended import create_access_token

from app import app, db
from models import Incident, Playbook, User
from services.incident_workflow import incident_sla_deadline
from services.ml_evaluation import evaluate_models
from services.playbook_safety import validate_actions


class WorkflowSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config.update(TESTING=True)

    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

        self.admin = User(username='test-admin', role='admin')
        self.admin.set_password('test-password')
        self.analyst = User(username='test-analyst', role='analyst')
        self.analyst.set_password('test-password')
        self.viewer = User(username='test-viewer', role='viewer')
        self.viewer.set_password('test-password')
        db.session.add_all([self.admin, self.analyst, self.viewer])
        db.session.flush()
        self.incident = Incident(
            title='Test incident',
            severity='High',
            status='open',
            timestamp=datetime.utcnow(),
            timeline='[]',
        )
        db.session.add(self.incident)
        db.session.commit()
        self.incident_id = self.incident.id
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def headers_for(self, username):
        return {'Authorization': f'Bearer {create_access_token(identity=username)}'}

    def test_sla_targets_and_timeline_are_consistent(self):
        created_at = datetime.utcnow()
        self.assertEqual(incident_sla_deadline('Critical', created_at), created_at + timedelta(hours=1))
        payload = self.incident.to_dict()
        self.assertEqual(
            payload['sla_due_at'],
            (self.incident.timestamp + timedelta(hours=4)).isoformat(),
        )
        self.assertFalse(payload['sla_breached'])

        response = self.client.put(
            f'/api/incidents/{self.incident_id}',
            headers=self.headers_for('test-analyst'),
            json={'status': 'investigating'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['timeline'][-1]['details'], {'from': 'open', 'to': 'investigating'})

        assignment = self.client.put(
            f'/api/incidents/{self.incident_id}/assign',
            headers=self.headers_for('test-analyst'),
            json={'assigned_to': self.analyst.id},
        )
        self.assertEqual(assignment.status_code, 200)
        self.assertEqual(assignment.json['assigned_to'], self.analyst.id)
        self.assertEqual(assignment.json['timeline'][-1]['action'], 'assigned')

    def test_invalid_assignment_and_status_are_rejected(self):
        headers = self.headers_for('test-analyst')
        status_response = self.client.put(
            f'/api/incidents/{self.incident_id}',
            headers=headers,
            json={'status': 'arbitrary'},
        )
        assignment_response = self.client.put(
            f'/api/incidents/{self.incident_id}/assign',
            headers=headers,
            json={'assigned_to': self.viewer.id},
        )
        self.assertEqual(status_response.status_code, 400)
        self.assertEqual(assignment_response.status_code, 400)

    def test_workflow_requires_approval_even_if_client_disables_it(self):
        response = self.client.post(
            '/api/soar/run',
            headers=self.headers_for('test-analyst'),
            json={
                'incident_id': self.incident_id,
                'playbook': 'containment',
                'requires_approval': False,
            },
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json['execution']['status'], 'pending_approval')
        self.assertEqual(Incident.query.get(self.incident_id).status, 'open')

        approval = self.client.post(
            f"/api/soar/executions/{response.json['execution']['id']}/approve",
            headers=self.headers_for('test-admin'),
        )
        self.assertEqual(approval.status_code, 200)
        self.assertEqual(approval.json['status'], 'completed')
        self.assertIn('Host isolation', approval.json['result']['manual_actions_required'][0])

    def test_dry_run_and_rejection_do_not_execute_actions(self):
        dry_run = self.client.post(
            '/api/soar/run',
            headers=self.headers_for('test-analyst'),
            json={'incident_id': self.incident_id, 'playbook': 'escalation', 'dry_run': True},
        )
        self.assertEqual(dry_run.status_code, 200)
        self.assertEqual(dry_run.json['execution']['status'], 'dry_run')
        self.assertEqual(Incident.query.get(self.incident_id).status, 'open')

        pending = self.client.post(
            '/api/soar/run',
            headers=self.headers_for('test-analyst'),
            json={'incident_id': self.incident_id, 'playbook': 'investigation'},
        )
        rejected = self.client.post(
            f"/api/soar/executions/{pending.json['execution']['id']}/reject",
            headers=self.headers_for('test-admin'),
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json['status'], 'rejected')
        self.assertEqual(Incident.query.get(self.incident_id).status, 'open')

    def test_rollback_restores_only_the_status_changed_by_execution(self):
        pending = self.client.post(
            '/api/soar/run',
            headers=self.headers_for('test-analyst'),
            json={'incident_id': self.incident_id, 'playbook': 'escalation'},
        )
        execution_id = pending.json['execution']['id']
        approved = self.client.post(
            f'/api/soar/executions/{execution_id}/approve',
            headers=self.headers_for('test-admin'),
        )
        self.assertEqual(approved.json['status'], 'completed')
        self.assertEqual(Incident.query.get(self.incident_id).status, 'escalated')

        rollback = self.client.post(
            f'/api/soar/executions/{execution_id}/rollback',
            headers=self.headers_for('test-admin'),
        )
        self.assertEqual(rollback.status_code, 200)
        self.assertEqual(rollback.json['status'], 'rollback_required')
        self.assertTrue(rollback.json['result']['rollback']['incident_status_restored'])
        self.assertEqual(Incident.query.get(self.incident_id).status, 'open')

    def test_notification_action_runs_only_after_approval(self):
        playbook = Playbook(
            name='Test notification',
            description='Approval-gated notification',
            trigger_severity='High',
            actions='["notify_slack"]',
            enabled=True,
        )
        db.session.add(playbook)
        db.session.commit()
        request = self.client.post(
            f'/api/playbooks/{playbook.id}/run',
            headers=self.headers_for('test-analyst'),
            json={'incident_id': self.incident_id},
        )
        self.assertEqual(request.status_code, 202)
        with patch('services.notifications.send_slack', return_value=True) as send_slack:
            approval = self.client.post(
                f"/api/soar/executions/{request.json['execution']['id']}/approve",
                headers=self.headers_for('test-admin'),
            )
        self.assertEqual(approval.status_code, 200)
        send_slack.assert_called_once()

    def test_playbook_action_allowlist(self):
        self.assertEqual(validate_actions(['notify_slack', 'notify_slack']), (['notify_slack'], None))
        actions, error = validate_actions(['arbitrary_command'])
        self.assertIsNone(actions)
        self.assertIsNotNone(error)

    def test_synthetic_model_evaluation_reports_metrics_and_counts(self):
        report = evaluate_models()
        self.assertIn('not a measure of production detection accuracy', report['dataset'])
        self.assertEqual(set(report['models']), {'log', 'network', 'user'})
        for metrics in report['models'].values():
            self.assertGreaterEqual(metrics['training_samples'], 20)
            self.assertEqual(metrics['evaluation_samples'], 16)
            self.assertIn('accuracy', metrics)
            self.assertIn('precision', metrics)
            self.assertIn('recall', metrics)
            self.assertIn('f1', metrics)
            self.assertEqual(
                sum(metrics['confusion_matrix'].values()),
                metrics['evaluation_samples'],
            )

        response = self.client.get(
            '/api/ml/evaluation',
            headers=self.headers_for('test-analyst'),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['models'], report['models'])


if __name__ == '__main__':
    unittest.main()
