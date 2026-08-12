"""
Real-Time Log Agent
-------------------
Watches system log files and forwards new entries to the SOAR SIEM API.

Supports:
  - Linux: /var/log/auth.log, /var/log/syslog
  - Custom log file via LOG_FILE env var

Usage:
  python3 log_agent.py

Environment Variables:
  API_URL   - Backend URL (default: http://localhost:5000)
  API_TOKEN - JWT token for authentication
  LOG_FILE  - Path to log file to watch (optional, overrides defaults)
  LOG_LEVEL - Logging verbosity (default: INFO)
"""

import os
import time
import requests
import platform
import logging

logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'),
                    format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

API_URL   = os.getenv('API_URL', 'http://localhost:5000')
API_TOKEN = os.getenv('API_TOKEN', '')

# Pick default log files based on OS
SYSTEM_LOG_FILES = {
    'Linux':  ['/var/log/auth.log', '/var/log/syslog'],
    'Darwin': ['/var/log/system.log'],
    'Windows': [],  # Windows Event Log needs a different approach
}

def get_log_files():
    """Return list of log files to watch."""
    custom = os.getenv('LOG_FILE')
    if custom:
        return [custom]
    return SYSTEM_LOG_FILES.get(platform.system(), [])


def send_log(line):
    """Send a single log line to the SIEM API."""
    line = line.strip()
    if not line:
        return

    headers = {'Content-Type': 'application/json'}
    if API_TOKEN:
        headers['Authorization'] = f'Bearer {API_TOKEN}'

    try:
        res = requests.post(
            f'{API_URL}/api/logs',
            json={'log': line},
            headers=headers,
            timeout=5
        )
        if res.status_code == 200:
            log.info(f'Sent: {line[:80]}')
        else:
            log.warning(f'API returned {res.status_code}: {res.text[:100]}')
    except requests.exceptions.ConnectionError:
        log.error(f'Cannot connect to {API_URL} — is the backend running?')
    except Exception as e:
        log.error(f'Failed to send log: {e}')


def tail_file(filepath):
    """Tail a file and yield new lines as they appear."""
    if not os.path.exists(filepath):
        log.warning(f'Log file not found: {filepath}')
        return

    log.info(f'Watching: {filepath}')

    with open(filepath, 'r', errors='replace') as f:
        # Start from end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.5)


def watch_files(files):
    """Watch multiple log files in separate threads."""
    import threading

    def watch(filepath):
        for line in tail_file(filepath):
            send_log(line)

    threads = []
    for filepath in files:
        t = threading.Thread(target=watch, args=(filepath,), daemon=True)
        t.start()
        threads.append(t)

    return threads


def login_and_get_token(username, password):
    """Login to SIEM and get a JWT token."""
    try:
        res = requests.post(
            f'{API_URL}/api/login',
            json={'username': username, 'password': password},
            timeout=5
        )
        if res.status_code == 200:
            token = res.json().get('token')
            log.info('Successfully authenticated with SIEM')
            return token
        else:
            log.error(f'Login failed: {res.text}')
    except Exception as e:
        log.error(f'Login error: {e}')
    return None


if __name__ == '__main__':
    # Auto-login if credentials are provided
    username = os.getenv('DEFAULT_ADMIN_USERNAME', 'admin')
    password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'password')

    if not API_TOKEN:
        log.info(f'Logging in as {username}...')
        token = login_and_get_token(username, password)
        if token:
            API_TOKEN = token
        else:
            log.warning('Running without authentication — logs may be rejected')

    files = get_log_files()

    if not files:
        log.error(
            'No log files to watch.\n'
            'Set LOG_FILE=/path/to/your.log or run on Linux with /var/log/auth.log'
        )
        exit(1)

    log.info(f'Starting Real-Time Log Agent → {API_URL}')
    log.info(f'Watching {len(files)} file(s): {", ".join(files)}')

    threads = watch_files(files)

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info('Log agent stopped.')
