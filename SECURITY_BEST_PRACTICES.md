# Security Best Practices & Hardening Guide

## 🔒 Pre-Deployment Security Checklist

### Critical (Must Do)
- [ ] Change DEFAULT_ADMIN_PASSWORD to a strong password
- [ ] Generate new SECRET_KEY (32+ random characters)
- [ ] Generate new JWT_SECRET_KEY (32+ random characters)
- [ ] Enable HTTPS/TLS with valid certificates
- [ ] Configure firewall to allow only necessary ports
- [ ] Update all dependencies to latest versions
- [ ] Review and update database security settings
- [ ] Configure backup and recovery procedures

### High Priority
- [ ] Enable audit logging for all authentication
- [ ] Set up monitoring and alerting
- [ ] Configure rate limiting on all public endpoints
- [ ] Enable CORS restrictions (already done)
- [ ] Set up SIEM monitoring for the SIEM itself
- [ ] Configure log retention and rotation
- [ ] Test incident response procedures
- [ ] Document security procedures

### Medium Priority
- [ ] Set up Web Application Firewall (WAF)
- [ ] Enable request/response logging
- [ ] Configure database encryption at rest
- [ ] Set up secure key storage (e.g., HashiCorp Vault)
- [ ] Enable two-factor authentication
- [ ] Configure IP whitelisting for admin panel
- [ ] Set up vulnerability scanning

---

## 🔐 Key Security Features Implemented

### 1. **JWT Token Expiration** ✅
- Tokens expire after 24 hours
- Reduces exposure window for stolen tokens
- Forces re-authentication periodically

**Configuration (in config.py):**
```python
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
```

### 2. **CORS Restrictions** ✅
- Only specified origins can access API
- Prevents cross-origin attacks

**Configuration (in app.py):**
```python
CORS(app, origins=[
    "http://localhost:3000",
    "http://localhost:5000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5000"
])
```

**For production, update to:**
```python
CORS(app, origins=[
    "https://yourdomain.com",
    "https://soc.yourdomain.com"
])
```

### 3. **Input Validation** ✅
- All endpoints validate input
- Prevents injection attacks
- Length checks on username/password

**Examples:**
- Login: Username max 80 chars, password max 256 chars
- Password: Minimum 6 characters
- Log: Maximum 10KB size
- Search: Minimum 2 characters

### 4. **SQL Injection Prevention** ✅
- Using SQLAlchemy ORM (parametrized queries)
- No raw SQL queries with user input

**Safe Example:**
```python
incidents = Incident.query.filter(
    Incident.title.ilike(f'%{query}%')
).all()
```

### 5. **Password Hashing** ✅
- Passwords hashed with Werkzeug security
- Using bcrypt under the hood
- Never stored in plaintext

**Code:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

user.password_hash = generate_password_hash(password)
user.check_password(password)  # Safe comparison
```

### 6. **XSS Prevention** ✅
- HTML escaping on log ingestion
- Control character removal
- Input sanitization

**Code (in routes/logs.py):**
```python
log_text = html.escape(log_text)
log_text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', log_text)
```

### 7. **Error Handling** ✅
- No sensitive information in error messages
- Proper exception handling
- Transaction rollback on failures

---

## 🛡️ Production Hardening

### 1. Enable HTTPS/TLS

**Using Let's Encrypt (Free):**
```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --standalone -d yourdomain.com

# Update docker-compose.yml to mount certificates
volumes:
  - /etc/letsencrypt/live/yourdomain.com/fullchain.pem:/app/certs/cert.pem
  - /etc/letsencrypt/live/yourdomain.com/privkey.pem:/app/certs/key.pem
```

**Using Self-Signed Certificates (Development):**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 2. Generate Strong Secrets

```bash
# Generate SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate JWT_SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Configure Environment Variables

**Never commit .env to git:**
```bash
echo ".env" >> .gitignore
```

**Use strong secrets in production:**
```
SECRET_KEY=<strong-random-string>
JWT_SECRET_KEY=<strong-random-string>
DEFAULT_ADMIN_PASSWORD=<complex-password>
```

### 4. Database Security

**Switch to PostgreSQL for production:**
```yaml
# Add to docker-compose.yml
postgres:
  image: postgres:15-alpine
  environment:
    POSTGRES_USER: soar_admin
    POSTGRES_PASSWORD: <strong-password>
    POSTGRES_DB: soar_siem
  volumes:
    - postgres-data:/var/lib/postgresql/data
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U soar_admin"]
```

**Update config.py:**
```python
DATABASE_URL = "postgresql://soar_admin:password@postgres:5432/soar_siem"
SQLALCHEMY_DATABASE_URI = DATABASE_URL
```

### 5. Rate Limiting Configuration

**Add to app.py (if Flask-Limiter installed):**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Apply to endpoints
@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per 15 minutes")
def login():
    ...

@incidents_bp.route("/search", methods=["GET"])
@limiter.limit("30 per minute")
def search_incidents():
    ...
```

### 6. Security Headers

**Add to app.py:**
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### 7. Logging & Monitoring

**Enable detailed logging:**
```python
import logging
logging.basicConfig(
    filename='siem.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

**Log authentication events:**
```python
logger.info(f"User {username} logged in from {request.remote_addr}")
logger.warning(f"Failed login attempt for {username}")
```

### 8. Regular Security Updates

**Check for vulnerabilities:**
```bash
pip audit
pip install --upgrade pip
pip install -r requirements.txt --upgrade
```

**Update base Docker images:**
```bash
docker pull python:3.11-slim
docker-compose build --no-cache
```

---

## 🔍 Security Audit Checklist

### Before Each Deployment
- [ ] All dependencies updated
- [ ] Security vulnerabilities scanned
- [ ] Database backups available
- [ ] SSL certificates valid
- [ ] Firewall rules reviewed
- [ ] Admin credentials changed
- [ ] Secrets rotated
- [ ] Logs reviewed for anomalies
- [ ] Monitoring configured
- [ ] Incident response plan tested

### Monthly
- [ ] Review access logs
- [ ] Check for failed login attempts
- [ ] Audit user permissions
- [ ] Review security patches
- [ ] Update threat intelligence feeds
- [ ] Test backup restoration
- [ ] Security team review

### Quarterly
- [ ] Penetration testing
- [ ] Vulnerability scanning
- [ ] Code security review
- [ ] Infrastructure audit
- [ ] Incident response drill
- [ ] Security training

---

## 🚨 Incident Response

### If Credentials Compromised

1. **Immediate Actions**
   - Reset all passwords immediately
   - Revoke all active sessions
   - Review access logs
   - Check for unauthorized changes

2. **Investigation**
   - What data was accessed?
   - How long was access active?
   - From which IP addresses?
   - Were other systems affected?

3. **Recovery**
   - Change all secrets/keys
   - Update database credentials
   - Restart all services
   - Restore from backup if needed

4. **Prevention**
   - Enable MFA
   - Restrict IP access
   - Increase monitoring
   - Implement WAF

### If Data Breach Detected

1. **Containment**
   - Isolate affected systems
   - Stop the bleeding
   - Preserve evidence

2. **Analysis**
   - What data was exposed?
   - How many records?
   - PII/sensitive data?

3. **Notification**
   - Legal team
   - Management
   - Customers (if applicable)
   - Authorities (if required)

4. **Remediation**
   - Fix vulnerability
   - Update security
   - Restore from backup

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.0.x/security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

## ✅ Sign-Off

This deployment has been reviewed for security best practices. All recommendations should be implemented before production use.

**Last Updated:** 2024-01-15
**Reviewed By:** Security Team
**Status:** ✅ Ready for Deployment (with recommendations implemented)

