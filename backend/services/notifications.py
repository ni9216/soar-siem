"""
Notifications Service
---------------------
Sends alerts via Email, Slack, and Discord.

Configure via environment variables:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
  SLACK_WEBHOOK_URL
  DISCORD_WEBHOOK_URL
"""

import os
import smtplib
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger(__name__)

# ── Email ────────────────────────────────────────────────
SMTP_HOST     = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT     = int(os.getenv('SMTP_PORT', 587))
SMTP_USER     = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_FROM     = os.getenv('SMTP_FROM', SMTP_USER)

# ── Slack ─────────────────────────────────────────────────
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')

# ── Discord ───────────────────────────────────────────────
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', '')


def send_email(to: str, subject: str, body: str) -> bool:
    """Send email alert. Returns True on success."""
    if not SMTP_USER or not SMTP_PASSWORD:
        log.warning('Email not configured (SMTP_USER/SMTP_PASSWORD missing)')
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = SMTP_FROM
        msg['To']      = to
        msg.attach(MIMEText(body, 'plain'))
        msg.attach(MIMEText(f"<pre>{body}</pre>", 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, to, msg.as_string())

        log.info(f'Email sent to {to}: {subject}')
        return True
    except Exception as e:
        log.error(f'Email failed: {e}')
        return False


def send_slack(message: str, severity: str = '') -> bool:
    """Post alert to Slack via webhook. Returns True on success."""
    if not SLACK_WEBHOOK_URL:
        log.warning('Slack not configured (SLACK_WEBHOOK_URL missing)')
        return False
    try:
        color = {'Critical': '#FF0000', 'High': '#FF6600',
                 'Medium': '#FFCC00', 'Low': '#00CC00'}.get(severity, '#888888')
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 SOAR SIEM Alert [{severity}]",
                "text": message,
                "footer": "SOAR SIEM",
            }]
        }
        res = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        res.raise_for_status()
        log.info(f'Slack alert sent: {message[:60]}')
        return True
    except Exception as e:
        log.error(f'Slack failed: {e}')
        return False


def send_discord(message: str, severity: str = '') -> bool:
    """Post alert to Discord via webhook. Returns True on success."""
    if not DISCORD_WEBHOOK_URL:
        log.warning('Discord not configured (DISCORD_WEBHOOK_URL missing)')
        return False
    try:
        color = {'Critical': 16711680, 'High': 16737792,
                 'Medium': 16776960, 'Low': 65280}.get(severity, 8947848)
        payload = {
            "embeds": [{
                "title": f"🚨 SOAR SIEM Alert [{severity}]",
                "description": message,
                "color": color,
                "footer": {"text": "SOAR SIEM"},
            }]
        }
        res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        res.raise_for_status()
        log.info(f'Discord alert sent: {message[:60]}')
        return True
    except Exception as e:
        log.error(f'Discord failed: {e}')
        return False


def notify_all(subject: str, message: str, severity: str = '', emails: list = None) -> dict:
    """Send to all configured channels. Returns dict of results."""
    results = {}
    if emails:
        results['email'] = all(send_email(e, subject, message) for e in emails)
    results['slack']   = send_slack(message, severity)
    results['discord'] = send_discord(message, severity)
    return results
