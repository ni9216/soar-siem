import requests
from models import db, ThreatFeed
from app import app

def fetch_threat_feeds():
    # Example: Fetch from AlienVault OTX
    api_key = app.config.get('THREAT_INTELLIGENCE_API_KEY')
    if not api_key:
        return

    # For demo, fetch indicators
    # In real implementation, integrate with actual feeds
    # Here, just add some dummy data
    dummy_indicators = [
        {'indicator': '192.168.1.100', 'type': 'IP', 'severity': 'High', 'source': 'AlienVault'},
        {'indicator': 'malicious.com', 'type': 'Domain', 'severity': 'Medium', 'source': 'AlienVault'}
    ]

    for item in dummy_indicators:
        if not ThreatFeed.query.filter_by(indicator=item['indicator']).first():
            feed = ThreatFeed(**item)
            db.session.add(feed)
    db.session.commit()