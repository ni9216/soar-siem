import requests
import logging
from datetime import datetime, timedelta
from models import db, ThreatFeed
from app import app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_threat_feeds():
    """
    Fetch threat intelligence from various sources
    """
    api_key = app.config.get('THREAT_INTELLIGENCE_API_KEY')
    
    if api_key:
        # Try real API integration
        fetch_from_alienvault(api_key)
    else:
        # Fallback to dummy data for demo
        logger.info("No API key provided, using dummy threat data")
        add_dummy_indicators()


def fetch_from_alienvault(api_key):
    """
    Fetch indicators from AlienVault OTX
    """
    try:
        # Get recent pulses (threat intelligence reports)
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {
            'X-OTX-API-KEY': api_key
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        indicators_added = 0
        
        for pulse in data.get('results', [])[:10]:  # Limit to 10 recent pulses
            for indicator in pulse.get('indicators', []):
                # Only add if not already in database
                if not ThreatFeed.query.filter_by(indicator=indicator['indicator']).first():
                    threat = ThreatFeed(
                        indicator=indicator['indicator'],
                        type=indicator['type'],
                        severity=map_otx_severity(indicator.get('type')),
                        source='AlienVault OTX',
                        description=pulse.get('name', ''),
                        last_seen=datetime.utcnow()
                    )
                    db.session.add(threat)
                    indicators_added += 1
        
        db.session.commit()
        logger.info(f"Added {indicators_added} indicators from AlienVault OTX")
        
    except requests.RequestException as e:
        logger.error(f"Failed to fetch from AlienVault: {e}")
        # Fallback to dummy data
        add_dummy_indicators()
    except Exception as e:
        logger.error(f"Error processing AlienVault data: {e}")
        add_dummy_indicators()


def map_otx_severity(indicator_type):
    """
    Map OTX indicator types to severity levels
    """
    high_severity_types = ['IPv4', 'IPv6', 'domain', 'hostname', 'URL']
    medium_severity_types = ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']
    
    if indicator_type in high_severity_types:
        return 'High'
    elif indicator_type in medium_severity_types:
        return 'Medium'
    else:
        return 'Low'


def add_dummy_indicators():
    """
    Add sample indicators for demo purposes
    """
    dummy_indicators = [
        {
            'indicator': '192.168.1.100', 
            'type': 'IPv4', 
            'severity': 'High', 
            'source': 'Demo Feed',
            'description': 'Known malicious IP',
            'last_seen': datetime.utcnow()
        },
        {
            'indicator': 'malicious.com', 
            'type': 'domain', 
            'severity': 'Medium', 
            'source': 'Demo Feed',
            'description': 'Suspicious domain',
            'last_seen': datetime.utcnow()
        },
        {
            'indicator': 'badguy.exe', 
            'type': 'FileHash-SHA256', 
            'severity': 'High', 
            'source': 'Demo Feed',
            'description': 'Malware hash',
            'last_seen': datetime.utcnow()
        }
    ]

    added = 0
    for item in dummy_indicators:
        if not ThreatFeed.query.filter_by(indicator=item['indicator']).first():
            feed = ThreatFeed(**item)
            db.session.add(feed)
            added += 1
    
    db.session.commit()
    logger.info(f"Added {added} dummy indicators")


def check_indicator(indicator):
    """
    Check if an indicator is in threat feeds
    """
    threat = ThreatFeed.query.filter_by(indicator=indicator).first()
    return threat.to_dict() if threat else None