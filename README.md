# Enterprise SOC Dashboard 🚀

A comprehensive Security Operations Center (SOC) platform with SIEM, SOAR, and threat intelligence capabilities. Built for modern cybersecurity operations with real-time monitoring, automated response, and advanced analytics.

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
- **JWT Authentication** - Secure user authentication and authorization
- **RESTful API** - Comprehensive API for integrations
- **SQLite Database** - Lightweight, file-based data storage

### Advanced Analytics
- **Severity Scoring** - Automatic risk assessment of security events
- **Correlation Engine** - Link related security events
- **Trend Analysis** - Historical security pattern analysis
- **Interactive Charts** - Visual security metrics and KPIs

## 🏗️ Architecture

### Backend (Flask + Python)
- **Flask** - Web framework with SocketIO for real-time communication
- **SQLAlchemy** - Database ORM with SQLite backend
- **JWT** - JSON Web Token authentication
- **Celery** - Asynchronous task processing for SOAR
- **In-Memory Services** - No external dependencies (Kafka, Elasticsearch, Redis alternatives)

### Frontend (React + Vite)
- **React 19** - Modern UI framework
- **Vite** - Fast development server and build tool
- **Socket.IO Client** - Real-time communication with backend
- **Recharts** - Interactive data visualization
- **TailwindCSS** - Utility-first CSS framework

### Self-Contained Services
- **In-Memory Message Queue** - Replaces Kafka for log processing
- **In-Memory Search Engine** - Replaces Elasticsearch for log indexing
- **In-Memory Cache** - Replaces Redis for session and task management

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd soc-dashboard
   ```

2. **Setup Backend**
   ```bash
   cd backend
   python -m venv ../.venv
   source ../.venv/bin/activate  # On Windows: ../.venv/Scripts/activate
   pip install -r requirements.txt
   ```

3. **Setup Frontend**
   ```bash
   cd ../frontend/soc-dashboard-frontend
   npm install
   ```

### Running the Application

1. **Start Backend Server**
   ```bash
   cd backend
   source ../.venv/bin/activate
   python app.py
   ```
   Backend will be available at: http://localhost:5000

2. **Start Frontend Dashboard**
   ```bash
   cd ../frontend/soc-dashboard-frontend
   npm run dev
   ```
   Frontend will be available at: http://localhost:5174

3. **Access the Dashboard**
   - Open http://localhost:5174 in your browser
   - Login with: `admin` / `admin`

## 📖 Usage

### Log Ingestion
Send security logs for processing:
```bash
curl -X POST http://localhost:5000/api/logs \
  -H "Content-Type: application/json" \
  -d '{"log":"Failed login attempt from IP 192.168.1.100"}'
```

### View Incidents
Get all security incidents:
```bash
curl http://localhost:5000/api/incidents
```

### Threat Scanning
Scan targets for vulnerabilities:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1"}'
```

### Authentication
Login to get JWT token:
```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

## 🔧 API Documentation

### Authentication Endpoints
- `POST /login` - User authentication
- `POST /register` - User registration

### Log Management
- `POST /api/logs` - Ingest security logs
- `GET /api/logs` - Retrieve processed logs

### Incident Management
- `GET /api/incidents` - List all incidents
- `GET /api/incidents/<id>` - Get specific incident
- `PUT /api/incidents/<id>` - Update incident status

### Threat Intelligence
- `GET /api/threats` - Query threat intelligence
- `POST /api/scan` - Perform security scans

### Real-time Features
- WebSocket events: `new_incident`, `log_stream`
- Automatic SOAR responses for critical/high severity events

## 🛠️ Development

### Project Structure
```
soc-dashboard/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── config.py              # Configuration settings
│   ├── models.py              # Database models
│   ├── routes/                # API endpoints
│   │   ├── auth.py           # Authentication
│   │   ├── incidents.py      # Incident management
│   │   ├── logs.py           # Log processing
│   │   └── scan.py           # Threat scanning
│   └── services/              # Business logic
│       ├── anomaly_engine.py  # ML anomaly detection
│       ├── correlation_engine.py
│       ├── severity_engine.py # Risk assessment
│       └── soar_engine.py     # Automated response
├── frontend/
│   └── soc-dashboard-frontend/
│       ├── src/
│       │   ├── App.jsx        # Main React app
│       │   ├── Dashboard.jsx  # Main dashboard
│       │   ├── Login.jsx      # Authentication UI
│       │   └── components/    # Reusable components
│       └── package.json
└── README.md
```

### Adding New Features

1. **Backend Services**: Add to `services/` directory
2. **API Endpoints**: Add to `routes/` directory
3. **Frontend Components**: Add to `frontend/src/components/`
4. **Database Models**: Update `models.py`

### Testing
```bash
# Backend tests
cd backend
python -m pytest

# Frontend tests
cd ../frontend/soc-dashboard-frontend
npm test
```

## 🔒 Security Features

- **JWT Authentication** - Secure token-based auth
- **Password Hashing** - bcrypt for secure password storage
- **CORS Protection** - Cross-origin request protection
- **Input Validation** - Comprehensive data validation
- **Role-based Access** - Admin and user roles

## 📊 Monitoring & Analytics

- **Real-time Dashboards** - Live security metrics
- **Incident Trends** - Historical analysis
- **Severity Distribution** - Risk visualization
- **Response Times** - Performance monitoring
- **Threat Intelligence** - External feed integration

## 🚀 Deployment

### Production Setup
1. Set environment variables:
   ```bash
   export JWT_SECRET_KEY="your-secret-key"
   export THREAT_INTELLIGENCE_API_KEY="your-api-key"
   ```

2. Use production WSGI server:
   ```bash
   pip install gunicorn
   gunicorn -w 4 app:app
   ```

3. Build frontend for production:
   ```bash
   npm run build
   ```

### Docker Alternative (Optional)
If you prefer Docker instead of in-memory services:
```bash
# Use docker-compose.yml for full infrastructure
docker-compose up -d
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the API endpoints

## 🎯 Roadmap

- [ ] Multi-tenant support
- [ ] Advanced ML models
- [ ] Integration with SIEM tools
- [ ] Custom dashboard widgets
- [ ] Alert notification channels
- [ ] Compliance reporting

---

**Built with ❤️ for cybersecurity professionals**</content>
<parameter name="filePath">/home/nicholas/ad-auditor/soc-dashboard/README.md