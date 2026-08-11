# SOAR SIEM - Troubleshooting Guide

## 🆘 Quick Diagnosis

### All Services Down
```bash
# 1. Check Docker status
docker-compose ps

# 2. Check logs
docker-compose logs

# 3. Check disk space
df -h

# 4. Restart everything
docker-compose down
docker-compose up -d
```

### Backend Won't Start
```bash
# Check logs
docker-compose logs backend

# Common causes:
# 1. Port 5000 in use
lsof -i :5000

# 2. Database locked
docker-compose exec backend rm db.sqlite
docker-compose restart backend

# 3. Missing dependencies
docker-compose build backend

# 4. Permission denied
docker-compose exec backend chmod 777 db.sqlite
```

### Database Issues
```bash
# Check database exists
docker-compose exec backend ls -la db.sqlite

# Initialize database
docker-compose exec backend python3 init_db.py

# Check database integrity
docker-compose exec backend sqlite3 db.sqlite "PRAGMA integrity_check;"

# Backup database
docker-compose exec backend cp db.sqlite db.sqlite.backup
```

### Socket.IO Not Working
```bash
# Check backend logs for Socket connection
docker-compose logs backend | grep -i socket

# Check frontend logs (browser console)
# Look for connection errors

# Verify CORS allows WebSocket
# Should see CORS headers in response

# Try direct connection
curl -N http://localhost:5000/socket.io/?transport=websocket
```

### Frontend Crashes
```bash
# Check browser console (F12)
# Look for JavaScript errors

# Check Error Boundary caught error
# Should show error details

# Clear cache and reload
# Ctrl+Shift+R or Cmd+Shift+R

# Check if backend is running
curl http://localhost:5000/api/status
```

---

## 🐛 Common Issues & Solutions

### Issue 1: "Connection Refused" on localhost:3000

**Symptoms:**
- Cannot access frontend at http://localhost:3000
- Browser shows "Connection refused"

**Solutions:**
```bash
# 1. Check if containers running
docker-compose ps

# 2. Check if port 3000 is available
lsof -i :3000

# 3. Check frontend logs
docker-compose logs frontend

# 4. Restart frontend
docker-compose restart frontend

# 5. Check docker network
docker network ls
docker network inspect soar-siem_default
```

---

### Issue 2: "Invalid Token" on Every Request

**Symptoms:**
- Login works
- All API requests return 401
- Token copied correctly

**Solutions:**
```bash
# 1. Check JWT configuration
curl http://localhost:5000/api/status  # Should work without token

# 2. Verify token format
# Should be: Bearer <token>

# 3. Check token expiration
# JWT tokens expire after 24 hours

# 4. Check backend logs
docker-compose logs backend | grep -i jwt

# 5. Re-login to get fresh token
```

**Token Format Check:**
```javascript
// In browser console
const token = localStorage.getItem('token');
if (token) {
  const decoded = JSON.parse(atob(token.split('.')[1]));
  console.log('Expires:', new Date(decoded.exp * 1000));
}
```

---

### Issue 3: Search Returns "No Results"

**Symptoms:**
- Search endpoint 404
- Search returns empty
- "Cannot POST /api/search" error

**Solutions:**
```bash
# 1. Verify endpoint exists
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:5000/api/search?q=test"

# 2. Test with valid query
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:5000/api/search?q=critical"

# 3. Check backend logs
docker-compose logs backend | grep search

# 4. Verify incidents exist
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:5000/api/incidents"

# 5. Restart backend if needed
docker-compose restart backend
```

---

### Issue 4: Slow Response Times

**Symptoms:**
- API requests take >5 seconds
- Dashboard loads slowly
- Database queries slow

**Solutions:**
```bash
# 1. Check system resources
docker stats

# 2. Check database size
docker-compose exec backend sqlite3 db.sqlite \
  "SELECT COUNT(*) FROM incident;"

# 3. Check backend logs for slow queries
docker-compose logs backend | grep "took"

# 4. Increase resource limits
# Edit docker-compose.yml and increase:
# memory: 1G (from 512M)
# cpus: 2 (from 1)

# 5. Archive old incidents
docker-compose exec backend sqlite3 db.sqlite \
  "DELETE FROM incident WHERE timestamp < date('now', '-30 days');"
```

---

### Issue 5: "Permission Denied" Errors

**Symptoms:**
- "Permission denied" when accessing files
- Database write failures
- Cannot create/update incidents

**Solutions:**
```bash
# 1. Check file permissions
docker-compose exec backend ls -la db.sqlite

# 2. Fix permissions
docker-compose exec backend chmod 666 db.sqlite

# 3. Fix app directory
docker-compose exec backend chmod 755 /app

# 4. Check running as correct user
docker-compose exec backend whoami

# 5. Rebuild container
docker-compose down
docker-compose build backend
docker-compose up -d backend
```

---

### Issue 6: "Cannot Connect to Kafka"

**Symptoms:**
- Logs show Kafka connection errors
- Log ingestion fails
- SOAR tasks don't run

**Solutions:**
```bash
# 1. Check Kafka is running
docker-compose ps | grep kafka

# 2. Check Kafka logs
docker-compose logs kafka

# 3. Test Kafka connection
docker-compose exec kafka kafka-broker-api-versions

# 4. Restart Kafka
docker-compose restart kafka

# 5. Check network connectivity
docker-compose exec backend \
  nc -zv kafka 9092
```

---

### Issue 7: "Elasticsearch Connection Failed"

**Symptoms:**
- "Cannot connect to Elasticsearch"
- Search indexing fails
- Logs show ES errors

**Solutions:**
```bash
# 1. Check Elasticsearch is running
docker-compose ps | grep elasticsearch

# 2. Check health
curl http://localhost:9200/_cluster/health

# 3. Check logs
docker-compose logs elasticsearch

# 4. Restart Elasticsearch
docker-compose restart elasticsearch

# 5. Check disk space (ES needs space)
docker exec elasticsearch df -h
```

---

### Issue 8: Database Keeps Getting Reset

**Symptoms:**
- Data disappears after restart
- No persistence
- Database always empty on startup

**Solutions:**
```bash
# 1. Check volume is mounted
docker-compose exec backend df -h | grep app

# 2. Check volume exists
docker volume ls | grep backend

# 3. Check docker-compose.yml
# Should have: volumes:
#              - backend-db:/app

# 4. Recreate volume
docker-compose down -v
docker-compose up -d
docker-compose exec backend python3 init_db.py

# 5. Verify persistence
# Add test incident
# Restart containers
# Incident should still exist
```

---

## 📊 Performance Tuning

### Optimize Database

```bash
# Analyze performance
docker-compose exec backend sqlite3 db.sqlite \
  "ANALYZE;"

# Create indexes
docker-compose exec backend sqlite3 db.sqlite \
  "CREATE INDEX idx_incident_severity ON incident(severity);"
docker-compose exec backend sqlite3 db.sqlite \
  "CREATE INDEX idx_incident_timestamp ON incident(timestamp);"

# Vacuum database
docker-compose exec backend sqlite3 db.sqlite \
  "VACUUM;"
```

### Increase Resource Limits

**In docker-compose.yml:**
```yaml
backend:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 1G
      reservations:
        cpus: '1'
        memory: 512M
```

### Enable Caching

**In frontend (Dashboard.jsx):**
```javascript
// Cache API responses
const cache = new Map();

const fetchWithCache = async (path, options = {}) => {
  if (cache.has(path)) {
    return cache.get(path);
  }
  const response = await fetch(path, options);
  const data = await response.json();
  cache.set(path, data);
  return data;
};
```

### Connection Pooling

**In config.py:**
```python
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}
```

---

## 🔍 Debugging Commands

### Get Full Service Status
```bash
docker-compose ps -a
docker-compose stats
docker system df
```

### View Specific Logs
```bash
# Last 50 lines
docker-compose logs --tail=50 backend

# Follow logs in real-time
docker-compose logs -f backend

# Specific time range
docker-compose logs --since 10m backend

# Search logs
docker-compose logs backend | grep "error"
```

### Execute Commands in Container
```bash
# Bash shell
docker-compose exec backend bash

# Python REPL
docker-compose exec backend python3

# Database CLI
docker-compose exec backend sqlite3 db.sqlite

# Install packages
docker-compose exec backend pip install package_name
```

### Network Debugging
```bash
# Check network
docker network ls
docker network inspect soar-siem_default

# Test connectivity
docker-compose exec backend nc -zv kafka 9092
docker-compose exec backend curl http://elasticsearch:9200

# Check DNS
docker-compose exec backend nslookup kafka
```

---

## 📈 Health Checks

### Manual Health Verification
```bash
# Backend API
curl http://localhost:5000/api/status

# Frontend (if built)
curl http://localhost:3000

# Kafka
docker-compose exec kafka kafka-broker-api-versions

# Elasticsearch
curl http://localhost:9200

# Redis
docker-compose exec redis redis-cli PING

# Database
docker-compose exec backend sqlite3 db.sqlite ".tables"
```

### Automated Monitoring
```bash
#!/bin/bash
# Save as health_check.sh

echo "=== SOAR SIEM Health Check ==="
echo "Timestamp: $(date)"

# Check services running
echo -n "Backend: "
curl -s http://localhost:5000/api/status | grep -q "OK" && echo "✓" || echo "✗"

echo -n "Frontend: "
curl -s http://localhost:3000 | grep -q "<!DOCTYPE" && echo "✓" || echo "✗"

echo -n "Database: "
docker-compose exec -T backend sqlite3 db.sqlite ".tables" > /dev/null 2>&1 && echo "✓" || echo "✗"

echo -n "Kafka: "
docker-compose exec -T kafka kafka-broker-api-versions > /dev/null 2>&1 && echo "✓" || echo "✗"

# Check disk space
echo "Disk Usage:"
docker system df
```

---

## 📞 Getting Help

1. **Check Logs First**
   ```bash
   docker-compose logs -f
   ```

2. **Verify All Services**
   ```bash
   docker-compose ps
   ```

3. **Test Connectivity**
   ```bash
   curl http://localhost:5000/api/status
   ```

4. **Review Documentation**
   - QUICK_START.md
   - API_DOCUMENTATION.md
   - SECURITY_BEST_PRACTICES.md

5. **Check GitHub Issues**
   - Common problems reported
   - Solutions from community

6. **Contact Administrator**
   - Provide full logs
   - Include docker-compose ps output
   - Describe steps to reproduce

---

## ✅ Verification Checklist

Before claiming "it works":

- [ ] Backend API responds to requests
- [ ] Frontend loads without errors
- [ ] Can login with credentials
- [ ] Dashboard displays incidents
- [ ] Search functionality works
- [ ] Real-time updates working (Socket.IO)
- [ ] Database persists after restart
- [ ] No errors in browser console
- [ ] No errors in docker logs
- [ ] Resource usage reasonable

