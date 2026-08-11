# SOAR SIEM API Documentation

## Base URL
```
http://localhost:5000/api
```

## Authentication
All endpoints require JWT token in the `Authorization` header:
```
Authorization: Bearer <your_jwt_token>
```

---

## 🔐 Authentication Endpoints

### POST `/api/login`
Login and get JWT token.

**Request:**
```json
{
  "username": "admin",
  "password": "your_password"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "admin"
}
```

**Error Responses:**
- 401: Invalid credentials
- 400: Missing username or password

---

### GET `/api/me`
Get current user profile.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "username": "admin",
  "role": "admin"
}
```

**Error Responses:**
- 401: Unauthorized

---

### POST `/api/register`
Create new user (admin only).

**Headers:**
```
Authorization: Bearer <admin_token>
```

**Request:**
```json
{
  "username": "analyst1",
  "password": "SecurePass123!",
  "role": "analyst"
}
```

**Response (201 Created):**
```json
{
  "message": "User created"
}
```

**Error Responses:**
- 400: Missing fields or invalid role
- 403: Unauthorized (not admin)

---

### GET `/api/users`
Get all users (admin only).

**Headers:**
```
Authorization: Bearer <admin_token>
```

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "username": "admin",
    "role": "admin"
  },
  {
    "id": 2,
    "username": "analyst1",
    "role": "analyst"
  }
]
```

---

### PUT `/api/users/<user_id>`
Update user (admin only).

**Request:**
```json
{
  "username": "newname",
  "password": "NewPassword123!",
  "role": "viewer"
}
```

**Response (200 OK):**
```json
{
  "id": 2,
  "username": "newname",
  "role": "viewer"
}
```

---

### DELETE `/api/users/<user_id>`
Delete user (admin only, cannot delete self).

**Response (200 OK):**
```json
{
  "message": "User deleted"
}
```

---

## 🚨 Incidents Endpoints

### GET `/api/incidents`
Get all incidents.

**Query Parameters:**
- None (returns all incidents)

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "title": "LOG [anomaly]",
    "severity": "Critical",
    "details": "Ransomware detected in network traffic",
    "time": "14:32:15",
    "timestamp": "2024-01-15T14:32:15.123456",
    "mitre_attack_id": "T1486",
    "status": "open",
    "assigned_to": null,
    "notes": ""
  }
]
```

---

### GET `/api/search`
Search incidents by title, details, or MITRE ID.

**Query Parameters:**
- `q` (required): Search query (minimum 2 characters)

**Example:**
```
GET /api/search?q=ransomware
```

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "title": "LOG [anomaly]",
    "severity": "Critical",
    "details": "Ransomware detected in network",
    "mitre_attack_id": "T1486",
    "timestamp": "2024-01-15T14:32:15.123456",
    "status": "open",
    "assigned_to": null,
    "notes": ""
  }
]
```

**Error Responses:**
- 400: Missing or too short query

---

### PUT `/api/incidents/<incident_id>`
Update incident status and notes.

**Request:**
```json
{
  "status": "investigating",
  "notes": "Isolating affected systems"
}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "title": "LOG [anomaly]",
  "severity": "Critical",
  "status": "investigating",
  "notes": "Isolating affected systems",
  "timestamp": "2024-01-15T14:32:15.123456"
}
```

**Allowed Status Values:**
- `open`
- `investigating`
- `escalated`
- `resolved`
- `closed`

---

### PUT `/api/incidents/<incident_id>/assign`
Assign incident to a user.

**Request:**
```json
{
  "assigned_to": 2
}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "title": "LOG [anomaly]",
  "assigned_to": 2,
  "timestamp": "2024-01-15T14:32:15.123456"
}
```

---

### GET `/api/stats`
Get incident statistics by severity.

**Response (200 OK):**
```json
{
  "Critical": 2,
  "High": 5,
  "Medium": 12,
  "Low": 28
}
```

---

### GET `/api/trends`
Get incident trends for last 24 hours.

**Response (200 OK):**
```json
[
  {
    "hour": "00:00",
    "value": 5
  },
  {
    "hour": "01:00",
    "value": 3
  },
  {
    "hour": "02:00",
    "value": 8
  }
]
```

---

## 📊 Logs Endpoints

### POST `/api/logs`
Ingest a security log.

**Request:**
```json
{
  "log": "Failed login attempt from 192.168.1.100"
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "severity": "Medium",
  "anomaly": "normal",
  "mitre_id": "T1110"
}
```

**Error Responses:**
- 400: Missing log field
- 500: Processing error

---

## 🔍 Threat Intelligence Endpoints

### GET `/api/threats`
Get all threat intelligence indicators.

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "indicator": "192.168.1.100",
    "type": "IP",
    "severity": "High",
    "source": "AbuseIPDB",
    "timestamp": "2024-01-15T14:32:15.123456",
    "description": "Known malicious IP address"
  }
]
```

---

### GET `/api/threats/abuseipdb`
Look up IP address in AbuseIPDB.

**Query Parameters:**
- `ip` (required): IP address to look up

**Example:**
```
GET /api/threats/abuseipdb?ip=192.168.1.100
```

**Response (200 OK):**
```json
{
  "ip": "192.168.1.100",
  "source": "AbuseIPDB",
  "abuse_confidence_score": 75,
  "abuse_percentage": 85,
  "country": "US",
  "report_count": 42,
  "last_reported": "2024-01-15T10:00:00Z",
  "domain": "example.com",
  "isp": "Example ISP",
  "hostnames": ["host1.example.com"],
  "raw_data": {}
}
```

**Note:** If ABUSEIPDB_API_KEY not configured, returns demo data.

---

## 🔐 Scan Endpoints

### POST `/api/scan`
Scan target host/IP for open ports.

**Request:**
```json
{
  "target": "192.168.1.1"
}
```

**Response (200 OK):**
```json
[
  {
    "host": "192.168.1.1",
    "port": 22,
    "state": "open"
  },
  {
    "host": "192.168.1.1",
    "port": 80,
    "state": "open"
  },
  {
    "host": "192.168.1.1",
    "port": 443,
    "state": "open"
  }
]
```

**Error Responses:**
- 400: Invalid target format
- 400: Target is localhost or reserved address
- 500: Scan failed

**Allowed Targets:**
- Valid IPv4 addresses (e.g., 8.8.8.8)
- Valid hostnames (e.g., example.com)

**Blocked Targets:**
- localhost
- 127.0.0.1
- 0.0.0.0
- 255.255.255.255

---

## 🤖 SOAR/Automation Endpoints

### POST `/api/soar/run`
Execute SOAR playbook on incident.

**Request:**
```json
{
  "incident_id": 1,
  "playbook": "investigation"
}
```

**Response (200 OK):**
```json
{
  "message": "SOAR playbook 'investigation' scheduled for incident 1.",
  "incident": {
    "id": 1,
    "title": "LOG [anomaly]",
    "status": "investigating",
    "timestamp": "2024-01-15T14:32:15.123456"
  }
}
```

**Available Playbooks:**
- `investigation` - Start investigation
- `containment` - Contain the threat
- `escalation` - Escalate to higher authority

---

## 📡 Status Endpoints

### GET `/api/status`
Health check endpoint.

**Response (200 OK):**
```json
{
  "status": "OK",
  "message": "Enterprise SIEM Running 🚀"
}
```

---

## 🔌 WebSocket Events (Socket.IO)

### Connection
```javascript
const socket = io('http://localhost:5000', {
  auth: { token: 'your_jwt_token' }
});
```

### Events Received

**new_incident**
```javascript
socket.on('new_incident', (incident) => {
  console.log('New incident:', incident);
});
```

**log_stream**
```javascript
socket.on('log_stream', (log) => {
  console.log('New log:', log);
});
```

**incident_update**
```javascript
socket.on('incident_update', (incident) => {
  console.log('Incident updated:', incident);
});
```

---

## Error Responses

All error responses follow this format:

```json
{
  "error": "Description of the error",
  "details": "Additional information (if available)"
}
```

### Common Error Codes

| Code | Meaning | Solution |
|------|---------|----------|
| 400 | Bad Request | Check request format and parameters |
| 401 | Unauthorized | Provide valid JWT token |
| 403 | Forbidden | You don't have permission for this action |
| 404 | Not Found | Resource doesn't exist |
| 500 | Server Error | Check backend logs |

---

## Rate Limiting

Currently no rate limiting is enforced. Recommended limits for production:
- Login: 5 requests per 15 minutes per IP
- Search: 30 requests per minute per user
- API: 100 requests per minute per user

See PERFORMANCE_GUIDE.md for implementation.

---

## Example: Complete Workflow

### 1. Login
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Response: {"token":"...", "role":"admin"}
```

### 2. Get Incidents
```bash
curl http://localhost:5000/api/incidents \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Search for Specific Incident
```bash
curl 'http://localhost:5000/api/search?q=ransomware' \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 4. Update Incident
```bash
curl -X PUT http://localhost:5000/api/incidents/1 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"investigating","notes":"Checking logs"}'
```

### 5. Run SOAR Playbook
```bash
curl -X POST http://localhost:5000/api/soar/run \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"incident_id":1,"playbook":"investigation"}'
```

---

## Testing with Postman/Insomnia

1. Set `base_url` variable: `http://localhost:5000/api`
2. Import requests from examples above
3. Set `token` variable after login
4. Use `{{token}}` in Authorization headers

---

## SDKs and Client Libraries

Currently available:
- JavaScript (fetch API)
- Python (requests library)

See code examples in `/examples` directory.

---

## Changelog

**Version 1.0 (Current)**
- Authentication (JWT)
- User management
- Incident management
- Search functionality
- Log ingestion
- Threat intelligence
- Port scanning
- SOAR automation
- Real-time updates (Socket.IO)

---

## Support

For issues or questions:
1. Check this documentation
2. See TROUBLESHOOTING_GUIDE.md
3. Check backend logs: `docker-compose logs -f backend`
4. Contact administrators

