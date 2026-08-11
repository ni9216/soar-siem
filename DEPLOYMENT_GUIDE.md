# Deployment & Configuration Guide

## 📋 Pre-Deployment Checklist

### 1. System Requirements
- [ ] Docker 20.10+
- [ ] Docker Compose 2.0+
- [ ] 4GB RAM minimum (8GB recommended)
- [ ] 20GB disk space minimum
- [ ] Port 3000, 5000, 9092, 9200, 6379 available

### 2. Environment Configuration
- [ ] Copy `.env.example` to `.env`
- [ ] Update all secrets in `.env`
- [ ] Set strong `DEFAULT_ADMIN_PASSWORD`
- [ ] Generate new `SECRET_KEY` and `JWT_SECRET_KEY`
- [ ] Review all configuration values

### 3. Security Review
- [ ] CORS origins configured for your domain
- [ ] HTTPS/TLS certificates obtained
- [ ] Firewall rules configured
- [ ] Network security reviewed
- [ ] Database backup strategy in place

### 4. Testing
- [ ] All containers start successfully
- [ ] Health checks pass
- [ ] Can login and access dashboard
- [ ] Search functionality works
- [ ] Real-time updates working
- [ ] Database persists after restart

---

## 🚀 Deployment Options

### Option 1: Local Development
```bash
# Perfect for: Learning, testing, development

cd /path/to/soar-siem
cp .env.example .env

# Update .env with your values
nano .env

# Start services
docker-compose up -d

# Check status
docker-compose ps

# Access dashboard
# http://localhost:3000
```

---

### Option 2: Single Server Production
```bash
# Perfect for: Small teams, 1-100 incidents/day

# 1. Update .env for production
ENVIRONMENT=production
SECRET_KEY=<generate-new>
JWT_SECRET_KEY=<generate-new>
DEFAULT_ADMIN_PASSWORD=<strong-password>

# 2. Enable SSL/TLS
# Add to docker-compose.yml:
# - /path/to/cert.pem:/app/cert.pem
# - /path/to/key.pem:/app/key.pem

# 3. Increase resource limits
# In docker-compose.yml:
# memory: 2G
# cpus: 2

# 4. Start services
docker-compose up -d

# 5. Verify deployment
docker-compose logs backend | head -20
```

---

### Option 3: High Availability Setup
```bash
# Perfect for: Enterprise, 24/7 operations, high volume

# Requirements:
# - Multiple servers
# - Load balancer (nginx, HAProxy)
# - PostgreSQL (instead of SQLite)
# - Redis cluster
# - Elasticsearch cluster
# - Kafka cluster

# Architecture:
# [Clients] -> [Load Balancer] -> [Backend Servers]
#              [PostgreSQL Server]
#              [Redis Cluster]
#              [Elasticsearch Cluster]

# 1. Deploy PostgreSQL
docker pull postgres:15-alpine
docker run -d \
  --name soar-postgres \
  -e POSTGRES_PASSWORD=<password> \
  -v postgres-data:/var/lib/postgresql/data \
  postgres:15-alpine

# 2. Deploy Redis Cluster
# (Use managed service or cluster setup)

# 3. Configure backend for HA
# - Multiple backend instances
# - Shared database
# - Session persistence

# 4. Configure load balancer
# (nginx/HAProxy pointing to multiple backends)
```

---

## 🔧 Environment Variables

### Backend Configuration

```bash
# Security
SECRET_KEY=<32-char-random>
JWT_SECRET_KEY=<32-char-random>

# Admin User
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_PASSWORD=<strong-password>

# Kafka (Message Queue)
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
KAFKA_TOPIC_LOGS=soc-logs

# Elasticsearch (Search)
ELASTICSEARCH_HOST=elasticsearch
ELASTICSEARCH_PORT=9200

# Redis (Cache & Celery)
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0

# Threat Intelligence APIs
THREAT_INTELLIGENCE_API_KEY=<optional>
ABUSEIPDB_API_KEY=<optional>

# Environment
ENVIRONMENT=development|staging|production
LOG_LEVEL=INFO|DEBUG|WARNING
```

### Frontend Configuration

```bash
# API URL
VITE_API_URL=http://localhost:5000
```

---

## 📦 Database Configuration

### Development (SQLite)
```python
# config.py
SQLALCHEMY_DATABASE_URI = "sqlite:///db.sqlite"
```

**Pros:**
- No setup required
- Good for development
- Data persists in volume

**Cons:**
- Single-threaded
- Not suitable for production
- Performance limited

---

### Production (PostgreSQL)

**1. Set up PostgreSQL:**
```bash
# Using Docker
docker run -d \
  --name soar-postgres \
  -e POSTGRES_USER=soar_admin \
  -e POSTGRES_PASSWORD=<password> \
  -e POSTGRES_DB=soar_siem \
  -v postgres-data:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:15-alpine
```

**2. Update config.py:**
```python
DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://soar_admin:password@postgres:5432/soar_siem'
)
SQLALCHEMY_DATABASE_URI = DATABASE_URL
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}
```

**3. Update .env:**
```
DATABASE_URL=postgresql://soar_admin:password@postgres:5432/soar_siem
```

**4. Migrate database:**
```bash
docker-compose exec backend python3 init_db.py
```

---

## 🔐 SSL/TLS Configuration

### Using Let's Encrypt

```bash
# 1. Install Certbot
sudo apt-get install certbot

# 2. Get certificate
sudo certbot certonly --standalone -d yourdomain.com

# 3. Add to docker-compose.yml
volumes:
  - /etc/letsencrypt/live/yourdomain.com/fullchain.pem:/app/cert.pem:ro
  - /etc/letsencrypt/live/yourdomain.com/privkey.pem:/app/key.pem:ro

# 4. Update backend to use SSL
# In app.py:
import ssl
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain('/app/cert.pem', '/app/key.pem')
socketio.run(app, host='0.0.0.0', port=5000, ssl_context=context)
```

### Self-Signed Certificate (Development)

```bash
# Generate certificate
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"

# Add to docker-compose.yml
volumes:
  - ./cert.pem:/app/cert.pem:ro
  - ./key.pem:/app/key.pem:ro
```

---

## 🔄 Backup & Restore

### Backup Database

```bash
# SQLite
docker-compose exec backend cp db.sqlite db.sqlite.backup

# PostgreSQL
docker-compose exec postgres pg_dump -U soar_admin soar_siem > backup.sql
```

### Restore Database

```bash
# SQLite
docker-compose exec backend cp db.sqlite.backup db.sqlite

# PostgreSQL
docker-compose exec postgres psql -U soar_admin soar_siem < backup.sql
```

### Backup All Data

```bash
#!/bin/bash
BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup database
docker-compose exec -T backend cp db.sqlite $BACKUP_DIR/db.sqlite

# Backup logs
docker-compose logs > $BACKUP_DIR/docker.log

# Backup configuration
cp .env $BACKUP_DIR/.env

echo "Backup completed: $BACKUP_DIR"
```

---

## 📊 Monitoring & Logging

### Set Up Log Aggregation

```bash
# Using Elasticsearch + Filebeat
# (Already included in docker-compose.yml)

# Logs are automatically indexed in Elasticsearch
# Query logs:
curl http://localhost:9200/soc-logs/_search
```

### Set Up Alerting

```bash
# Using Elasticsearch Watcher
# Create rule for critical incidents

curl -X PUT localhost:9200/_watcher/watch/critical-incidents \
  -H 'Content-Type: application/json' \
  -d '{
    "trigger": {"schedule": {"interval": "5m"}},
    "input": {"search": {"request": {"index": ["soc-logs"]}}},
    "condition": {"script": {"source": "_score > 5"}},
    "actions": {"send_alert": {"webhook": {"url": "..."}}}
  }'
```

---

## 🚄 Performance Optimization

### Database Optimization

```bash
# Create indexes
docker-compose exec backend sqlite3 db.sqlite << EOF
CREATE INDEX idx_incident_severity ON incident(severity);
CREATE INDEX idx_incident_status ON incident(status);
CREATE INDEX idx_incident_timestamp ON incident(timestamp);
EOF
```

### Caching Configuration

```python
# In config.py
REDIS_URL = 'redis://redis:6379/0'
CACHE_TYPE = 'RedisCache'
CACHE_DEFAULT_TIMEOUT = 300
```

### Connection Pooling

```python
# Already configured in config.py
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,
    'pool_recycle': 3600,
}
```

---

## 🔑 Secrets Management (Production)

### Using Environment Variables
```bash
# Create .env file (not in git)
SECRET_KEY=<random>
JWT_SECRET_KEY=<random>
DEFAULT_ADMIN_PASSWORD=<password>
```

### Using HashiCorp Vault

```bash
# 1. Install Vault
curl -sSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault

# 2. Store secrets
vault kv put secret/soar/backend \
  secret_key="..." \
  jwt_secret_key="..." \
  admin_password="..."

# 3. Access in application
import hvac
client = hvac.Client(url='http://vault:8200')
secrets = client.secrets.kv.read_secret_version(path='soar/backend')
```

---

## 🧪 Testing Deployment

### Smoke Tests

```bash
#!/bin/bash
# Save as smoke_test.sh

TOKEN=$(curl -s -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}' \
  | jq -r '.token')

echo "Testing endpoints..."

# Health check
curl -s http://localhost:5000/api/status | jq .

# Get incidents
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/incidents | jq .

# Get stats
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/stats | jq .

echo "✓ All tests passed"
```

### Load Testing

```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:5000/api/status

# Using wrk (more advanced)
wrk -t4 -c100 -d30s http://localhost:5000/api/status
```

---

## 📈 Scaling Considerations

### Vertical Scaling (Add Resources)
```bash
# Increase memory and CPU in docker-compose.yml
# Increase database connection pool
# Add caching layer
```

### Horizontal Scaling (Add Servers)
```bash
# Run multiple backend instances
# Use load balancer
# Shared database (PostgreSQL)
# Shared cache (Redis cluster)
# Shared message queue (Kafka cluster)
```

---

## ✅ Deployment Verification

After deployment, verify:

```bash
#!/bin/bash
echo "=== SOAR SIEM Deployment Verification ==="

# 1. Services running
echo "✓ Services:"
docker-compose ps

# 2. Health checks
echo "✓ Health Status:"
curl -s http://localhost:5000/api/status | jq .

# 3. Database
echo "✓ Database:"
docker-compose exec -T backend sqlite3 db.sqlite "SELECT COUNT(*) FROM incident;"

# 4. Frontend
echo "✓ Frontend:"
curl -s http://localhost:3000 | grep -q "SOC Dashboard" && echo "  OK" || echo "  FAIL"

# 5. Logs
echo "✓ Errors:"
docker-compose logs | grep -i error | tail -5 || echo "  No errors"

echo "=== Deployment Complete ==="
```

