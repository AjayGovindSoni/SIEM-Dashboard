# 🛡️ SIEM Dashboard

A full-stack **Security Information and Event Management (SIEM)** system built with FastAPI and React. Ingests security logs, detects threats using correlation rules, and presents findings through a real-time interactive dashboard.

> Built as an internship project to demonstrate enterprise security monitoring concepts.

---

## 📸 Preview

| Dashboard | Events | Incidents |
|-----------|--------|-----------|
| Event timeline, severity charts, top source IPs | Filterable security event log | Correlated incident tracking with risk scores |

---

## ✨ Features

- **Real-time Dashboard** — auto-refreshes every 30 seconds with live event data
- **Log Ingestion** — Syslog UDP (port 5514) and TCP (port 5515) receivers, plus file monitoring
- **Multi-format Parsing** — RFC3164/RFC5424 syslog, Apache logs, JSON, with auto-detection
- **Correlation Engine** — detects brute force, port scans, web attacks, and anomaly spikes
- **Incident Management** — auto-creates incidents with risk scores and severity levels
- **Alert Notifications** — email (Gmail App Password), Slack webhook, and custom webhooks
- **REST API** — full FastAPI backend with Swagger docs at `/docs`
- **CSV Export** — export events for offline analysis
- **Attack Simulator** — built-in sample log generator for testing and demos

---

## 🏗️ Architecture

```
Log Sources (Syslog / Files)
         │
         ▼
 Ingestion Layer (UDP 5514 / TCP 5515)
         │
         ▼
 Multi-format Parser → Normalizer
         │
         ▼
 SQLite Database (SecurityEvent, Incident, Alert, Rule)
         │
         ▼
 Correlation Engine (Brute Force, Port Scan, Web Attack, Anomaly)
         │
         ▼
 FastAPI REST API (:8001)
         │
         ▼
 React Dashboard (:5173)
```

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Recharts, Lucide Icons |
| Backend | FastAPI, SQLAlchemy, Uvicorn |
| Database | SQLite (dev) |
| Notifications | SMTP (Gmail), Slack Webhooks |
| Dev Server | Vite 7 with API proxy |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Node.js 20+ (use `nvm install 22` if needed)

### 1. Clone the repo

```bash
git clone https://github.com/your-username/siem-dashboard.git
cd siem-dashboard
```

### 2. Set up environment variables

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` with your values (see [Configuration](#️-configuration) below).

### 3. Run

```bash
chmod +x start.sh
./start.sh
```

Choose an option:
- **1** — Start backend + frontend
- **2** — Start backend + frontend + generate sample data ← recommended for first run
- **3** — Generate sample data only

### 4. Open the dashboard

```
http://localhost:5173
```

API docs available at `http://localhost:8001/docs`

---

## 📁 Project Structure

```
siem-dashboard/
├── backend/
│   ├── main_enhanced.py        # FastAPI app + all API routes
│   ├── models.py               # SQLAlchemy models (Event, Incident, Alert, Rule)
│   ├── log_parser.py           # Multi-format log parsers
│   ├── correlation.py          # Threat correlation engine
│   ├── syslog_receiver.py      # UDP/TCP syslog listeners
│   ├── notifications.py        # Email, Slack, webhook alerts
│   ├── sample_log_generator.py # Attack simulation tool
│   ├── requirements_enhanced.txt
│   ├── .env.example            # ← copy this to .env
│   └── siem.db                 # SQLite DB (auto-created, gitignored)
├── frontend/
│   └── myapp/
│       ├── src/
│       │   ├── components/
│       │   │   └── SIEMDashboard.jsx   # Main dashboard component
│       │   ├── App.jsx
│       │   ├── main.jsx
│       │   └── index.css
│       ├── index.html
│       └── vite.config.js      # Includes /api proxy to backend
├── start.sh                    # One-command startup script
├── .gitignore
└── README.md
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/events` | List events (filter by severity, IP, time, search) |
| GET | `/api/events/{id}` | Get single event |
| GET | `/api/events/stats/summary` | Event counts by severity and category |
| GET | `/api/events/stats/timeline` | Event volume over time |
| GET | `/api/events/export/csv` | Export events as CSV |
| GET | `/api/incidents` | List all incidents |
| GET | `/api/incidents/{id}` | Get single incident |
| GET | `/api/stats/top-sources` | Top source IPs by event count |
| GET | `/api/rules` | List correlation rules |
| GET | `/api/geo/map` | Geolocation data for source IPs |

Full interactive docs at **`http://localhost:8001/docs`**

---

## 🧪 Generating Sample Data

```bash
cd backend
source venv/bin/activate

# Full simulation (normal traffic + all attack types)
python sample_log_generator.py --mode full

# Specific attack types
python sample_log_generator.py --mode brute-force
python sample_log_generator.py --mode port-scan
python sample_log_generator.py --mode web-attack

# Normal traffic only (custom count)
python sample_log_generator.py --mode normal --count 100
```

---

## 🔴 Alert Notifications

Alerts fire automatically based on incident severity:

| Severity | Email | Slack | Webhook |
|----------|-------|-------|---------|
| Critical | ✅ | ✅ | ✅ |
| High | ✅ | ✅ | ❌ |
| Medium / Low | ✅ | ❌ | ❌ |

All three channels are optional. If not configured in `.env`, they're silently skipped — no crashes.

---

## 📡 Connecting Real Log Sources

**Forward system logs via rsyslog:**
```bash
# Add to /etc/rsyslog.conf
*.* @your-siem-ip:5514    # UDP
*.* @@your-siem-ip:5515   # TCP

sudo systemctl restart rsyslog
```

**Monitor local log files** — edit `backend/main_enhanced.py` startup section:
```python
ingestion_manager.add_file_monitor([
    '/var/log/auth.log',
    '/var/log/nginx/access.log',
], parser_format='auto')
```

---

## 🐛 Troubleshooting

**Dashboard shows no data**
- Make sure you're opening `http://localhost:5173`, not `http://localhost:8001`
- The backend (8001) is the raw API — the frontend (5173) is the dashboard
- Run option 2 in `start.sh` to generate sample data

**Vite fails with Node version error**
```bash
nvm install 22
nvm use 22
nvm alias default 22   # make it permanent
```

**Email alerts not sending**
- Gmail requires an App Password, not your account password
- Generate one at: https://myaccount.google.com/apppasswords
- Make sure 2-Step Verification is enabled on your Google account first

---

## 📄 License

MIT — free for personal, educational, and commercial use.

---

<p align="center">Made with ☕ and way too many security logs</p>
