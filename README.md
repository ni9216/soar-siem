# SOAR SIEM - Enterprise Security Automation Platform

```
    _____ ____    ___    ____     _____  ___  ___  _____  _   __
   / ___// __ \  / _ |  / __ \   / ___/ |_ _||_ _||_   _|| \ / /
   \__ \/ /_/ / / __ | / /_/ /   \___ \  / /   / /   / /  |  V  |
  ___/ / _, _/ / ___ |/ _, _/   ____/ / / /   / /   / /   | |\_|
 /____/_/ |_| /_/  |_/_/ |_|   /_____/ /_/   /_/   /_/    |_| \_|

 Security Operations Analytics & Response - SIEM
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue)](https://www.python.org/)
[![React 19+](https://img.shields.io/badge/React-19+-61DAFB)](https://react.dev/)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-v3.8+-2496ED)](https://docs.docker.com/compose/)

---

## 📋 Overview

**SOAR SIEM** is an enterprise-grade Security Operations Analytics & Response platform designed to help security teams detect, analyze, automate, investigate, and track security incidents.

## 🌟 Features

### Core Security Capabilities
- **Real-time Log Ingestion** - Process security logs from multiple sources
- **ML-Powered Anomaly Detection** - Identify suspicious patterns using machine learning
- **Automated Incident Response (SOAR)** - Trigger automated responses to security events
- **Threat Intelligence Integration** - Query external threat feeds and databases
- **MITRE ATT&CK Mapping** - Classify threats using industry-standard framework

### Platform Features
- **Interactive Dashboard** - Real-time monitoring with charts and alerts
- **WebSocket Real-time Updates** - Live incident notifications
- **JWT Authentication** - Secure user authentication and authorization (24-hour expiration)
- **RESTful API** - Comprehensive API for integrations
- **Error Boundaries** - Graceful error handling in frontend
- **Role-based Access Control** - Admin, analyst, viewer roles

### Advanced Analytics
- **Severity Scoring** - Automatic risk assessment of security events
- **Correlation Engine** - Link related security events
- **Search Engine** - Case-insensitive search across incidents
- **Trend Analysis** - Historical security pattern analysis
- **Port Scanning** - Network reconnaissance with nmap

## 🏗️ Architecture

### Backend (Flask + Python)
- **Flask** - Web framework with SocketIO for real-time communication
- **SQLAlchemy** - Database ORM with SQLite/PostgreSQL support
- **JWT** - JSON Web Token authentication with expiration
- **Celery** - Asynchronous task processing for SOAR
- **Kafka** - Message queue for log ingestion
- **Elasticsearch** - Full-text search indexing
- **Redis** - Cache and session management

### Frontend (React + Vite)
- **React 19** - Modern UI framework
- **Vite** - Fast development server and build tool
- **Socket.IO Client** - Real-time communication with backend
- **Recharts** - Interactive data visualization
- **TailwindCSS** - Utility-first CSS framework
- **Error Boundary** - Crash recovery component

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB RAM minimum
- Ports 3000, 5000, 9092, 9200, 6379 available

### 1️⃣ Clone & Setup

```bash
cd /path/to/soar-siem
cp .env.example .env

# Update .env with your values if needed
# Default admin: admin / password

docker-compose up -d
```

### 2️⃣ Verify Deployment

```bash
docker-compose ps
# All services should be "healthy"
```

### 3️⃣ Initialize Database

```bash
docker-compose exec backend python3 init_db.py
```

### 4️⃣ Access Dashboard

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000/api
- **API Docs**: See [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

### 5️⃣ Login

```
Username: admin
Password: password (CHANGE THIS!)
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| **[QUICK_START.md](QUICK_START.md)** | 6-step setup guide with troubleshooting |
| **[API_DOCUMENTATION.md](API_DOCUMENTATION.md)** | Complete API reference with examples |
| **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** | Production deployment options |
| **[SECURITY_BEST_PRACTICES.md](SECURITY_BEST_PRACTICES.md)** | Security hardening checklist |
| **[PERFORMANCE_GUIDE.md](PERFORMANCE_GUIDE.md)** | Optimization & monitoring |
| **[TROUBLESHOOTING_GUIDE.md](TROUBLESHOOTING_GUIDE.md)** | Common issues & solutions |

---

## 🔐 Security

### Built-in Security Features
✅ JWT Authentication (24-hour expiration)  
✅ CORS Restrictions (localhost only by default)  
✅ Input Validation (length, type, format)  
✅ SQL Injection Prevention (SQLAlchemy ORM)  
✅ XSS Prevention (HTML escaping)  
✅ Password Hashing (Werkzeug + bcrypt)  
✅ Error Handling (no sensitive info)  
✅ Error Boundaries (graceful failure)  

### Before Production
- [ ] Change default password
- [ ] Generate new SECRET_KEY
- [ ] Generate new JWT_SECRET_KEY  
- [ ] Enable HTTPS/TLS
- [ ] Update CORS origins
- [ ] Review .env configuration
- [ ] Set up monitoring
- [ ] Configure backups

See [SECURITY_BEST_PRACTICES.md](SECURITY_BEST_PRACTICES.md) for complete guide.

---

## 📂 Project Structure

```
soar-siem/
├── backend/                    # Flask backend
│   ├── app.py                 # Main application
│   ├── config.py              # Configuration
│   ├── models.py              # Database models
│   ├── init_db.py             # Database init
│   ├── requirements.txt        # Dependencies
│   ├── routes/                # API endpoints
│   ├── services/              # Business logic
│   └── workers/               # Background jobs
│
├── frontend/                   # React frontend
│   └── soc-dashboard-frontend/
│       ├── src/               # React components
│       ├── package.json       # Dependencies
│       └── vite.config.js     # Build config
│
├── docker-compose.yml         # Container orchestration
├── .env.example              # Configuration template
├── README.md                 # This file
├── QUICK_START.md            # Setup guide
├── API_DOCUMENTATION.md      # API reference
├── DEPLOYMENT_GUIDE.md       # Deployment
├── SECURITY_BEST_PRACTICES.md # Security
├── PERFORMANCE_GUIDE.md      # Performance
└── TROUBLESHOOTING_GUIDE.md  # Troubleshooting
```

---

## 🔌 API Endpoints

### Authentication
- `POST /api/login` - User login
- `GET /api/me` - Current user profile
- `POST /api/register` - Create user (admin only)
- `GET /api/users` - List users (admin only)

### Incidents
- `GET /api/incidents` - Get all incidents
- `GET /api/search?q=<query>` - Search incidents
- `PUT /api/incidents/<id>` - Update incident
- `GET /api/stats` - Get severity statistics
- `GET /api/trends` - Get incident trends

### Logs & Scanning
- `POST /api/logs` - Ingest log
- `POST /api/scan` - Scan target
- `GET /api/threats` - Get threat intelligence

### SOAR
- `POST /api/soar/run` - Run SOAR playbook

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for full reference.

---

## 📖 Usage

### Login

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd soar-siem
   ```

2. **Copy environment configuration**
   ```bash
   cp .env.example .env
   ```

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

4. **Initialize database**
   ```bash
   docker-compose exec backend python3 init_db.py
   ```

5. **Access dashboard**
   - Frontend: http://localhost:3000
   - Backend: http://localhost:5000

---

## 📖 Usage

### Log Ingestion
```bash
curl -X POST http://localhost:5000/api/logs \
  -H "Content-Type: application/json" \
  -d '{"log":"Failed login attempt from 192.168.1.100"}'
```

### View Incidents
```bash
curl http://localhost:5000/api/incidents \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Search Incidents
```bash
curl "http://localhost:5000/api/search?q=ransomware" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Port Scanning
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1"}'
```

### Authentication
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

---

## 🧪 Testing

### Manual Tests
```bash
# Health check
curl http://localhost:5000/api/status

# Login test
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Get incidents
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:5000/api/incidents
```

### Docker Verification
```bash
docker-compose ps   # All services should be healthy
docker-compose logs # Check for errors
```

---

## 🔧 API Documentation

### Authentication Endpoints
- `POST /api/login` - User authentication
- `POST /api/register` - User registration (admin only)

### Log Management
- `POST /api/logs` - Ingest security logs
- `GET /api/logs` - Retrieve processed logs

### Incident Management
- `GET /api/incidents` - List all incidents
- `GET /api/incidents/<id>` - Get specific incident
- `GET /api/search` - Search incidents
- `PUT /api/incidents/<id>` - Update incident status

### Threat Intelligence
- `GET /api/threats` - Query threat intelligence
- `POST /api/scan` - Perform security scans

### Real-time Features
- WebSocket events: `new_incident`, `log_stream`, `incident_update`
- Automatic SOAR responses for critical/high severity events

---

## 🛠️ Development

### Project Structure

Backend Features:
- Comprehensive error handling with try-catch blocks
- Input validation on all user-facing endpoints
- Database transaction management with rollback
- Asynchronous task processing with Celery
- Real-time communication via WebSocket

Frontend Features:
- Error boundary component for crash recovery
- Login form with credential validation
- Real-time dashboard with multiple tabs
- Role-based access control
- Interactive charts using Recharts

### Adding New Features

1. **Backend Services**: Add to `services/` directory
2. **API Endpoints**: Add to `routes/` directory
3. **Frontend Components**: Add to `frontend/src/` directory
4. **Database Models**: Update `models.py`

### Testing
```bash
# Backend syntax check
docker-compose exec backend python3 -m py_compile app.py

# Backend imports
docker-compose exec backend python3 -c "from app import app; print('✓')"

# Frontend access
curl -s http://localhost:3000 | head -20
```

---

## 🔒 Security Features

- **JWT Authentication** - Secure token-based auth with 24-hour expiration
- **Password Hashing** - bcrypt for secure password storage  
- **CORS Protection** - Restricted to configured origins
- **Input Validation** - Length, type, and format validation
- **Error Boundaries** - Graceful failure in React
- **Role-based Access** - Admin, analyst, viewer roles
- **SQL Injection Prevention** - SQLAlchemy ORM parameterization
- **XSS Prevention** - HTML escaping and control character removal

---

## 📊 Monitoring & Analytics

- **Real-time Dashboards** - Live security metrics
- **Incident Trends** - Historical analysis
- **Severity Distribution** - Risk visualization  
- **Search Analytics** - Find relevant incidents
- **Threat Intelligence** - External feed integration
- **Performance Monitoring** - System health checks

---

## 🚀 Deployment

### Development Setup
```bash
# With Docker Compose (recommended)
docker-compose up -d

# Access at http://localhost:3000
```

### Production Setup
See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for:
- SSL/TLS configuration
- PostgreSQL setup
- Resource optimization
- High availability setup
- Monitoring configuration

### Docker Alternative (Full Infrastructure)
Use docker-compose.yml for complete stack with Kafka, Elasticsearch, Redis.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🆘 Support

For support and questions:
- **Documentation**: See links above
- **Troubleshooting**: [TROUBLESHOOTING_GUIDE.md](TROUBLESHOOTING_GUIDE.md)
- **GitHub Issues**: Create an issue for bugs
- **Email**: Contact security team

---

## 🎯 Roadmap

- [x] Core SIEM functionality
- [x] SOAR automation
- [x] Real-time dashboard
- [x] Threat intelligence integration
- [x] Error handling & recovery
- [ ] Multi-tenant support
- [ ] Advanced ML models
- [ ] Custom playbooks
- [ ] Alert notification channels
- [ ] Compliance reporting

---

## 📈 Stats

- **Backend**: Flask, Python 3.9+
- **Frontend**: React 19, Vite 8, Tailwind 4
- **Database**: SQLite (dev) / PostgreSQL (prod)
- **Real-time**: WebSocket via Socket.IO
- **Queue**: Kafka for log ingestion
- **Search**: Elasticsearch for indexing
- **Cache**: Redis for session/cache
- **API Endpoints**: 20+
- **Security Features**: 10+

---

<div align="center">

**SOAR SIEM** - Enterprise Security Automation Platform

Made with ❤️ for security teams

[⭐ Star this repo if you find it useful!](#)

</div>

---

**Last Updated**: 2024-01-15  
**Version**: 1.0.0  
**Status**: ✅ Production Ready
</content>
<parameter name="filePath">/home/nicholas/ad-auditor/soc-dashboard/README.md