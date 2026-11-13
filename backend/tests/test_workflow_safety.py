import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

os.environ['DATABASE_URL'] = 'sqlite://'

from flask_jwt_extended import create_access_token

from app import app, db
from models import AlertGroup, Asset, AuditLog, Incident, Playbook, SecurityEvent, User, db
from services.incident_workflow import incident_sla_deadline
from services.ingestion import normalize_event
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

    def test_scan_requires_active_registered_asset_and_scanner_role(self):
        invalid_target = self.client.post(
            '/api/scan',
            headers=self.headers_for('test-analyst'),
            json={'target': '127.0.0.1'},
        )
        self.assertEqual(invalid_target.status_code, 400)

        response = self.client.post(
            '/api/scan',
            headers=self.headers_for('test-analyst'),
            json={'target': '192.0.2.10'},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn('active, registered assets', response.json['error'])

        asset = Asset(name='Inactive scan target', ip_address='192.0.2.10', status='inactive')
        db.session.add(asset)
        db.session.commit()
        response = self.client.post(
            '/api/scan',
            headers=self.headers_for('test-analyst'),
            json={'target': asset.ip_address},
        )
        self.assertEqual(response.status_code, 403)

        asset.status = 'active'
        db.session.commit()
        response = self.client.post(
            '/api/scan',
            headers=self.headers_for('test-viewer'),
            json={'target': asset.ip_address},
        )
        self.assertEqual(response.status_code, 403)

    def test_scan_runs_only_for_registered_active_asset(self):
        target = '192.0.2.10'
        db.session.add(Asset(name='Registered scan target', ip_address=target, status='active'))
        db.session.commit()

        scanner = MagicMock()
        scanner.all_hosts.return_value = [target]
        host_scanner = MagicMock()
        host_scanner.all_protocols.return_value = ['tcp']
        host_scanner.__getitem__.return_value = {443: {'state': 'open'}}
        scanner.__getitem__.return_value = host_scanner
        nmap_module = SimpleNamespace(
            PortScanner=Mock(return_value=scanner),
            PortScannerError=RuntimeError,
        )
        with patch.dict('sys.modules', {'nmap': nmap_module}):
            response = self.client.post(
                '/api/scan',
                headers=self.headers_for('test-analyst'),
                json={'target': target},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, [{'host': target, 'port': 443, 'state': 'open'}])
        scanner.scan.assert_called_once_with(target, arguments='-sV -p 1-1024')

    def test_scan_reports_nmap_runtime_unavailable(self):
        target = '192.0.2.10'
        db.session.add(Asset(name='Registered scan target', ip_address=target, status='active'))
        db.session.commit()

        nmap_module = SimpleNamespace(
            PortScanner=Mock(side_effect=RuntimeError('nmap executable not found')),
            PortScannerError=RuntimeError,
        )
        with patch.dict('sys.modules', {'nmap': nmap_module}):
            response = self.client.post(
                '/api/scan',
                headers=self.headers_for('test-analyst'),
                json={'target': target},
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn('Nmap is not installed', response.json['error'])

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

    def test_incident_updates_are_recorded_in_audit_trail(self):
        response = self.client.put(
            f'/api/incidents/{self.incident_id}',
            headers=self.headers_for('test-analyst'),
            json={'status': 'investigating', 'notes': 'Reviewed by analyst'},
        )
        self.assertEqual(response.status_code, 200)
        entry = AuditLog.query.filter_by(action='incident.updated').order_by(AuditLog.id.desc()).first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actor, 'test-analyst')
        self.assertEqual(entry.details, '{"status": "investigating", "notes_updated": true}')

    def test_sysmon_source_ingests_windows_event_json(self):
        source_response = self.client.post(
            '/api/ingestion/sources',
            headers=self.headers_for('test-admin'),
            json={'name': 'Sysmon test host', 'source_type': 'windows_event'},
        )
        self.assertEqual(source_response.status_code, 201)
        api_key = source_response.json['api_key']
        payload = {
            'EventID': 3,
            'EventRecordID': 8181,
            'UtcTime': '2026-11-10T07:00:00Z',
            'Computer': 'WS-01',
            'User': 'DOMAIN\\analyst',
            'EventData': {
                'SourceIp': '10.0.0.12',
                'DestinationIp': '203.0.113.8',
                'DestinationPort': '443',
                'Image': 'C:\\Windows\\System32\\example.exe',
            },
        }
        with patch('routes.ingestion.process_security_event.apply'):
            response = self.client.post(
                '/api/ingest',
                headers={'X-API-Key': api_key},
                json=payload,
            )
            retry = self.client.post(
                '/api/ingest',
                headers={'X-API-Key': api_key},
                json=payload,
            )
        self.assertEqual(response.status_code, 202)
        self.assertTrue(retry.json['duplicate'])
        event = SecurityEvent.query.filter_by(event_id=response.json['event_id']).one()
        self.assertEqual(event.event_type, 'Sysmon NetworkConnect')
        self.assertEqual(event.host, 'WS-01')
        self.assertEqual(event.username, 'DOMAIN\\analyst')
        self.assertEqual(event.source_ip, '10.0.0.12')
        self.assertEqual(event.destination_ip, '203.0.113.8')
        self.assertIn('NetworkConnect', event.message)
        self.assertEqual(event.occurred_at, datetime(2026, 11, 10, 7, 0))

    def test_identical_alerts_are_suppressed_within_window(self):
        with patch('routes.logs.full_analysis', return_value={'anomaly': 'Normal'}), \
             patch('services.correlation_engine.check_attack_chains', return_value=[]), \
             patch('services.threat_feed_auto.scan_log_for_iocs', return_value=[]), \
             patch('routes.playbooks.run_playbook_for_incident'):
            first = self.client.post(
                '/api/logs',
                headers=self.headers_for('test-analyst'),
                json={'log': 'Repeated failed login from 192.0.2.44'},
            )
            duplicate = self.client.post(
                '/api/logs',
                headers=self.headers_for('test-analyst'),
                json={'log': 'Repeated failed login from 192.0.2.44'},
            )
            setting = self.client.put(
                '/api/alert-deduplication',
                headers=self.headers_for('test-admin'),
                json={'window_minutes': 0},
            )
            after_disable = self.client.post(
                '/api/logs',
                headers=self.headers_for('test-analyst'),
                json={'log': 'Repeated failed login from 192.0.2.44'},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(duplicate.status_code, 200)
        self.assertTrue(duplicate.json['deduplicated'])
        self.assertEqual(setting.status_code, 200)
        self.assertEqual(after_disable.status_code, 200)
        self.assertFalse(after_disable.json.get('deduplicated', False))
        self.assertEqual(Incident.query.filter_by(details='Repeated failed login from 192.0.2.44').count(), 2)
        group = AlertGroup.query.get(first.json['alert_group_id'])
        self.assertEqual(group.incident_count, 3)
        self.assertEqual(group.suppressed_count, 1)

    def test_detection_rule_create_update_and_test(self):
        created = self.client.post(
            '/api/rules',
            headers=self.headers_for('test-admin'),
            json={'name': 'Suspicious marker', 'pattern': 'encoded payload', 'severity': 'High'},
        )
        self.assertEqual(created.status_code, 201)
        rule_id = created.json['id']
        updated = self.client.put(
            f'/api/rules/{rule_id}',
            headers=self.headers_for('test-admin'),
            json={'enabled': False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertFalse(updated.json['enabled'])
        tested = self.client.post(
            f'/api/rules/{rule_id}/test',
            headers=self.headers_for('test-admin'),
            json={'log': 'Observed ENCODED PAYLOAD in process command line'},
        )
        self.assertEqual(tested.status_code, 200)
        self.assertTrue(tested.json['matched'])

    def test_health_and_local_backup_tools(self):
        health = self.client.get('/api/operations/health', headers=self.headers_for('test-admin'))
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json['database'], 'healthy')
        self.assertEqual(health.json['ingestion']['failed'], 0)

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / 'source.sqlite'
            backup_directory = Path(directory) / 'backups'
            with sqlite3.connect(database_path) as connection:
                connection.execute('CREATE TABLE backup_test (value TEXT)')
                connection.execute("INSERT INTO backup_test VALUES ('preserved')")
            with patch('routes.enterprise._sqlite_database_path', return_value=database_path), \
                 patch('routes.enterprise._sqlite_backup_directory', return_value=backup_directory):
                created = self.client.post('/api/admin/backups', headers=self.headers_for('test-admin'))
                self.assertEqual(created.status_code, 201)
                listed = self.client.get('/api/admin/backups', headers=self.headers_for('test-admin'))
                self.assertEqual(listed.status_code, 200)
                self.assertEqual(len(listed.json), 1)
                downloaded = self.client.get(
                    f"/api/admin/backups/{created.json['filename']}",
                    headers=self.headers_for('test-admin'),
                )
                self.assertEqual(downloaded.status_code, 200)
                self.assertTrue(downloaded.data.startswith(b'SQLite format 3'))
            backup_path = backup_directory / created.json['filename']
            self.assertTrue(backup_path.exists())
            self.assertEqual(backup_path.stat().st_mode & 0o777, 0o600)
            with sqlite3.connect(backup_path) as connection:
                self.assertEqual(connection.execute('SELECT value FROM backup_test').fetchone()[0], 'preserved')

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
