# SOAR SIEM - Complete Setup Guide

## 🚀 Quick Start (5 minutes)

### Prerequisites
- Docker and Docker Compose installed
- Git (optional)

### Step 1: Clone/Navigate to Project
```bash
cd /home/liech/project/soar-siem
```

### Step 2: Create Environment File
```bash
cp .env.example .env
```

### Step 3: Update Credentials (IMPORTANT!)
```bash
# Edit .env and change:
# - DEFAULT_ADMIN_PASSWORD to something strong
# - SECRET_KEY and JWT_SECRET_KEY to random values

# Generate strong keys:
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))"
```

### Step 4: Start All Services
```bash
docker-compose up -d
```

### Step 5: Verify Services
```bash
# Check all containers are running
docker-compose ps

# Check backend health
curl http://localhost:5000/api/status

# Check logs if needed
docker-compose logs -f backend
```

### Step 6: Access the Application
- **Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **Default Credentials**: Set in .env file

---

## 📊 Service Details

### Backend (Flask)
- **Port**: 5000
- **Health Check**: http://localhost:5000/api/status
- **Documentation**: See API_DOCUMENTATION.md

### Frontend (React + Vite)
- **Port**: 3000
- **Dev Mode**: `npm run dev` (in frontend folder)
- **Production Build**: `npm run build`

### Database
- **Type**: SQLite (development) or PostgreSQL (production)
- **Location**: `/backend/db.sqlite` (SQLite)
- **Auto-initialized**: Yes (via init_db.py)

### Kafka (Message Queue)
- **Port**: 9092
- **Admin UI**: Not included, use CLI or third-party tools
- **Auto Topics**: Enabled

### Elasticsearch (Search)
- **Port**: 9200
- **UI**: http://localhost:9200/_plugin/kibana (if Kibana added)

### Redis (Cache & Celery)
- **Port**: 6379
- **Persistence**: Enabled (RDB + AOF)

---

## 🔐 Security Checklist

### Before First Deployment
- [ ] Changed DEFAULT_ADMIN_PASSWORD
- [ ] Generated new SECRET_KEY
- [ ] Generated new JWT_SECRET_KEY
- [ ] Configured HTTPS/TLS (production)
- [ ] Set up firewall rules
- [ ] Changed default Kafka credentials
- [ ] Enabled authentication on Redis

### Before Production
- [ ] Switch from SQLite to PostgreSQL
- [ ] Enable SSL/TLS certificates
- [ ] Set up log aggregation
- [ ] Configure backup strategy
- [ ] Set up monitoring/alerting
- [ ] Run security audit
- [ ] Configure rate limiting (see PERFORMANCE_GUIDE.md)

---

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check logs
docker-compose logs backend

# Common issues:
# 1. Port 5000 in use: Change in docker-compose.yml
# 2. Database locked: Remove db.sqlite and restart
# 3. Dependencies missing: Check requirements.txt installed correctly
```

### Database not persisting
```bash
# Check volume created
docker volume ls | grep backend

# Check volume mount
docker inspect soc-backend | grep -A 5 Mounts
```

### Socket.IO not connecting
```bash
# Check backend logs for connection errors
docker-compose logs backend | grep -i socket

# Verify CORS is configured correctly
# Check frontend console for connection errors
```

### Search not working
```bash
# Test search endpoint directly
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:5000/api/search?q=test"

# Check backend logs for errors
docker-compose logs backend | grep -i search
```

---

## 📝 Common Tasks

### Initialize Database Manually
```bash
docker-compose exec backend python3 init_db.py
```

### View Backend Logs
```bash
docker-compose logs -f backend
```

### Restart a Service
```bash
docker-compose restart backend
docker-compose restart frontend
```

### Clean Up Everything
```bash
# Stop and remove containers
docker-compose down

# Remove volumes (WARNING: data loss!)
docker-compose down -v

# Rebuild images
docker-compose build --no-cache
```

### Connect to Database
```bash
# SQLite
docker-compose exec backend sqlite3 db.sqlite

# PostgreSQL (if using)
docker-compose exec postgres psql -U admin -d siem
```

---

## 🔄 Development Workflow

### Local Development (Without Docker)
```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py

# Frontend (separate terminal)
cd frontend/soc-dashboard-frontend
npm install
npm run dev
```

### Docker Development
```bash
# Make code changes
# Changes auto-sync (volumes mounted)

# Restart only changed service
docker-compose restart backend

# Rebuild if requirements changed
docker-compose build backend
docker-compose up -d backend
```

---

## 📚 Documentation Files

- **DEPLOYMENT_GUIDE.md** - Production deployment
- **API_DOCUMENTATION.md** - All API endpoints
- **CONFIGURATION_GUIDE.md** - Environment variables
- **SECURITY_BEST_PRACTICES.md** - Security hardening
- **PERFORMANCE_GUIDE.md** - Optimization tips
- **TROUBLESHOOTING_GUIDE.md** - Common issues

---

## 🆘 Getting Help

### Check Logs
```bash
docker-compose logs [service]
docker-compose logs -f backend
docker-compose logs --tail=100 backend
```

### Common Error Codes
- 401: Unauthorized (invalid/expired token)
- 403: Forbidden (insufficient permissions)
- 404: Not found (endpoint doesn't exist)
- 500: Server error (check backend logs)

### Enable Debug Mode
```bash
# In docker-compose.yml, change:
# ENVIRONMENT=development (adds extra logging)
```

---

## ✨ Next Steps

1. Create `.env` file from `.env.example`
2. Update credentials and secrets
3. Run `docker-compose up -d`
4. Access http://localhost:3000
5. Log in with credentials from `.env`
6. Test features using API_DOCUMENTATION.md
7. Configure threat intelligence APIs (optional)
8. Set up monitoring and alerting (optional)

Enjoy your SOAR SIEM! 🚀
