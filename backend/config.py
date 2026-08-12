import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Database — uses PostgreSQL in production, SQLite for local dev
    DATABASE_URL = os.getenv('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        # Render provides postgres://, SQLAlchemy needs postgresql://
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = DATABASE_URL or ('sqlite:///' + os.path.join(BASE_DIR, 'db.sqlite'))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True}

    SECRET_KEY = os.getenv('SECRET_KEY', '_H0QUXmJGSxjQ658IxaVLKLaqf2XpTr--R2YzwcYgfc')
    
    # Kafka settings
    KAFKA_BOOTSTRAP_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
    KAFKA_TOPIC_LOGS = 'soc-logs'
    
    # Elasticsearch settings
    ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'localhost')
    ELASTICSEARCH_PORT = int(os.getenv('ELASTICSEARCH_PORT', 9200))
    
    # JWT settings - ADD EXPIRATION
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'WvTjGx3yViS3mgauiWlYU6p7TZkxh9hX5t1aiD45260')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Token expires in 24 hours
    
    # Redis for Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    
    # Threat Intelligence API settings
    THREAT_INTELLIGENCE_API_KEY = os.getenv('THREAT_INTELLIGENCE_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress={ip}'
