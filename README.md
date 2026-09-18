# Intelligent Login Attempt Monitoring and Intrusion Detection System (IDS)

A production-ready, portfolio-grade Cyber Security web application engineered with Python (Flask), MySQL/SQLite dual-engine database architecture, Bootstrap 5 glassmorphism theme, dynamic threat detection heuristics, machine learning risk vector scoring, and separate User and Admin Security Operations Center (SOC) dashboards.

---

## 🌟 Key Features

### 1. Advanced Intrusion Detection & Threat Prevention
- **Brute Force Defense**: Automatically locks accounts and triggers security alerts after configurable consecutive failed login attempts.
- **Password Spraying & Credential Stuffing Detection**: Monitors IP-to-username ratio and flags multi-account high-frequency attack patterns.
- **Impossible Travel Velocity**: Identifies geographically anomalous logins across distant locations within impossible timeframes.
- **TOR Node & Suspicious IP Intelligence**: Detects exit nodes, malicious proxy headers, and automated bot User-Agent strings (`Python-urllib`, `Go-http-client`).

### 2. AI-Powered Risk Scoring Engine
- Computes real-time **Risk Score (0.0 to 100.0)** and assigns risk levels: `Safe`, `Low`, `Medium`, `High`, `Critical`.
- **Adaptive Step-Up MFA**: Automatically prompts users for secondary 6-digit OTP verification when risk score exceeds safety thresholds (>= 65.0).

### 3. Intelligent Account Recovery System
- **Anti-Compromise Security**: Prevents attackers from unlocking accounts simply via compromised email accounts.
- **Multi-Factor Unlock**: Supports 8-character Emergency Backup Recovery Codes, Trusted Device fingerprint validation, and identity checks.

### 4. Separate User & Admin Dashboards
- **User Security Dashboard**:
  - Security Health Score posture indicator.
  - Granular Login Audit History (IP, Browser, OS, Device, Risk Level).
  - Active Session Management with remote session revocation.
  - Trusted Devices authorization center.
  - Emergency Recovery Code generator.
- **Admin SOC Operations Center**:
  - Key Performance Indicators (Total Users, Verified, Blocked, Failed Logins, Active Alerts).
  - Top Attacker IP & Top Target User threat analytics.
  - Live Plotly.js charts (hourly login trends, risk score breakdown, attack vector radar).
  - User Management with manual Lock/Unlock controls.
  - System Audit Log viewer.
  - Automated PDF (ReportLab), CSV (Pandas), and Excel report generator.

---

## 📁 Project Architecture

```text
ids_cyber_security/
│
├── run.py                     # Main application entry point & auto-initialization
├── config.py                  # System security parameters & environment settings
├── requirements.txt           # Python dependency specifications
├── README.md                  # System documentation & setup guide
│
├── app/
│   ├── __init__.py            # Flask App Factory & Login Manager setup
│   │
│   ├── database/              # Database Abstraction Layer
│   │   ├── db.py              # SQLite/MySQL dual-engine context manager
│   │   ├── schema.sql         # Production normalized database DDL
│   │   └── init_db.py         # DB schema builder & seed script
│   │
│   ├── models/                # Data Entities
│   │   ├── user.py            # User model & password bcrypt hashing
│   │   └── security.py        # LoginAttempt, SecurityAlert, TrustedDevice models
│   │
│   ├── services/              # Core Intelligence Engines
│   │   ├── threat_detector.py # Rule-based & heuristic threat engine
│   │   ├── ai_risk_engine.py  # ML vector risk scoring engine
│   │   ├── otp_service.py     # OTP, reset token, & recovery code engine
│   │   └── report_generator.py# ReportLab PDF & Pandas CSV/Excel exporter
│   │
│   ├── routes/                # Application Controllers & Blueprints
│   │   ├── auth_routes.py     # Login, Register, OTP, Recovery, Step-Up MFA
│   │   ├── user_routes.py     # User Security Dashboard controller
│   │   ├── admin_routes.py    # Admin SOC Dashboard controller
│   │   └── api_routes.py      # REST JSON endpoints for Plotly charts
│   │
│   ├── utils/                 # Security Decorators & Request Parsers
│   │   ├── security_helpers.py# Client IP parser & user-agent extractor
│   │   └── decorators.py      # @admin_required & @verified_required guards
│   │
│   ├── static/                # Front-End Assets
│   │   ├── css/styles.css     # Cyber Glassmorphism & Neon Theme
│   │   └── js/
│   │       ├── main.js        # Canvas device fingerprint generator
│   │       └── soc_charts.js  # Plotly.js chart renderers
│   │
│   └── templates/             # Jinja2 HTML Templates
│       ├── layout.html        # Main base layout with navbar & alerts
│       ├── index.html         # Landing page with Live Threat Simulator
│       ├── auth/              # Authentication & Recovery templates
│       ├── user/              # User Dashboard templates
│       └── admin/             # Admin SOC Command Portal templates
│
├── logs/                      # System audit log storage
└── reports/                   # Exported PDF, CSV, and Excel audit files
```

---

## 🛠️ Quick Start Guide

### 1. Prerequisites
- Python 3.9+
- MySQL (Optional for production; defaults to SQLite zero-config mode)

### 2. Installation & Setup
```bash
# Clone or navigate to directory
cd C:\Users\dhadu\.gemini\antigravity\scratch\ids_cyber_security

# Install Python dependencies
pip install -r requirements.txt

# Run database schema builder & seed script
python app/database/init_db.py

# Launch the Application
python run.py
```

### 3. Accessing the Application
Open your web browser and navigate to: `http://127.0.0.1:5000/`

#### 🔑 Demo Accounts
- **Admin SOC Account**:
  - Email: `admin@security.soc`
  - Password: `Admin@123456`
- **Standard User Account**:
  - Email: `john@example.com`
  - Password: `User@123456`
- **Locked Target Account (Simulated Attack)**:
  - Email: `bob@example.com`
  - Password: `User@123456`
