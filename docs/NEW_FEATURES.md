# SIEM Dashboard - New Features Guide

This document describes the newly added features: Authentication, Alert Notifications, CSV Export, and Geographic Mapping.

## 🔐 Authentication & Authorization

### Overview
JWT-based authentication with role-based access control (RBAC).

### Roles
- **admin**: Full access, can create rules and users
- **analyst**: Can view and modify incidents, trigger alerts
- **viewer**: Read-only access to dashboard

### Setup

1. **Start the Enhanced Backend**:
```bash
cd backend
pip install -r requirements_enhanced.txt
python main_enhanced.py
```

2. **Default Admin Account**:
- Username: `admin`
- Password: `admin123`
- ⚠️ **CHANGE THIS IMMEDIATELY IN PRODUCTION!**

### API Usage

#### Register New User
```bash
curl -X POST http://localhost:8001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst1",
    "email": "analyst@company.com",
    "password": "securepass123",
    "role": "analyst"
  }'
```

#### Login
```bash
curl -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer"
}
```

#### Using the Token
```bash
# Set token
TOKEN="your-jwt-token-here"

# Make authenticated request
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/auth/me
```

### Protected Endpoints

| Endpoint | Role Required |
|----------|--------------|
| POST /api/events | Any authenticated user |
| GET /api/events/export/csv | Any authenticated user |
| PATCH /api/incidents/{id} | Any authenticated user |
| POST /api/incidents/{id}/alert | analyst or admin |
| POST /api/rules | admin only |

### Frontend Integration

```javascript
// Login
const response = await fetch('http://localhost:8001/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'admin123' })
});

const { access_token } = await response.json();
localStorage.setItem('token', access_token);

// Make authenticated requests
const eventsResponse = await fetch('http://localhost:8001/api/events/export/csv', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('token')}`
  }
});
```

---

## 🔔 Alert Notifications

### Overview
Automatic notifications when security incidents are detected. Supports Email, Slack, and generic webhooks.

### Configuration

Configure via `backend/.env` (never hardcode credentials):

```python
```env
# backend/.env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
CUSTOM_WEBHOOK_URL=https://your-endpoint.com/alerts
```
```

### Gmail Setup

1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password:
   - Go to: https://myaccount.google.com/apppasswords
   - Select "Mail" and your device
   - Copy the 16-character password
3. Use this app password in `SMTP_PASSWORD`

### Slack Setup

1. Go to https://api.slack.com/apps
2. Create a new app
3. Enable "Incoming Webhooks"
4. Add webhook to workspace
5. Copy the webhook URL
6. Paste into `SLACK_WEBHOOK_URL`

### Automatic Alerts

Alerts are automatically sent when incidents are created:

- **Critical severity**: Email + Slack + Webhook
- **High severity**: Email + Slack
- **Medium/Low/Info**: Email only

### Manual Alerts

Trigger an alert manually:

```bash
curl -X POST http://localhost:8001/api/incidents/1/alert \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "methods": ["email", "slack"],
    "recipients": ["analyst@company.com", "manager@company.com"]
  }'
```

### Alert Types

#### Email Alert
- Plain text and HTML versions
- Includes incident details, severity, risk score
- Links to SIEM dashboard
- Color-coded by severity

#### Slack Alert
- Rich formatting with attachments
- Color-coded sidebar
- Emoji indicators for severity
- Direct link to incident

#### Webhook Alert
- JSON payload with full incident data
- Timestamp in ISO format
- Can integrate with: PagerDuty, ServiceNow, Splunk, etc.

### Testing Alerts

```python
# Test email
from notifications import EmailNotifier, AlertNotificationConfig
from models import Incident

config = AlertNotificationConfig()
notifier = EmailNotifier(config)

# Create test incident
incident = Incident(
    id=999,
    title="Test Alert",
    severity="high",
    risk_score=75.0,
    description="This is a test alert",
    source_ip="192.168.1.100",
    event_count=5
)

notifier.send(incident, ["your-email@gmail.com"])
```

---

## 📊 CSV Export

### Overview
Export security events to CSV format for external analysis, reporting, or archiving.

### Usage

```bash
# Export last 24 hours
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/events/export/csv" \
  -o events.csv

# Export with filters
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/events/export/csv?severity=high&limit=5000" \
  -o high_severity_events.csv

# Export date range
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/events/export/csv?start_time=2024-02-01T00:00:00Z&end_time=2024-02-04T23:59:59Z" \
  -o february_events.csv
```

### CSV Format

Columns:
- ID
- Timestamp
- Source IP
- Destination IP
- Source Port
- Destination Port
- Username
- Hostname
- Event Type
- Severity
- Category
- Message
- Risk Score
- Correlated

### Limits

- Maximum: 50,000 events per export
- For larger exports, use date range filtering

### Frontend Integration

```javascript
const downloadCSV = async () => {
  const token = localStorage.getItem('token');
  
  const response = await fetch(
    'http://localhost:8001/api/events/export/csv?limit=1000',
    {
      headers: { 'Authorization': `Bearer ${token}` }
    }
  );
  
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'siem_events.csv';
  a.click();
};
```

---

## 🗺️ Geographic Mapping

### Overview
Visualize attack sources on a world map using IP geolocation.

### IP Geolocation Service

The system uses the free ip-api.com service by default. No API key required!

#### Lookup Single IP

```bash
curl http://localhost:8001/api/geo/lookup/8.8.8.8
```

Response:
```json
{
  "ip": "8.8.8.8",
  "country": "United States",
  "country_code": "US",
  "region": "California",
  "city": "Mountain View",
  "latitude": 37.4056,
  "longitude": -122.0775,
  "timezone": "America/Los_Angeles",
  "isp": "Google LLC",
  "org": "Google Public DNS",
  "as": "AS15169 Google LLC"
}
```

#### Get Map Data

```bash
curl "http://localhost:8001/api/geo/map?limit=1000"
```

Response:
```json
{
  "locations": [
    {
      "ip": "203.0.113.45",
      "country": "United States",
      "latitude": 37.7749,
      "longitude": -122.4194,
      "event_count": 156
    },
    ...
  ]
}
```

### Frontend Map Integration

Install Leaflet for React:

```bash
npm install react-leaflet leaflet
```

Example component:

```javascript
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

const GeoMap = () => {
  const [locations, setLocations] = useState([]);
  
  useEffect(() => {
    fetch('http://localhost:8001/api/geo/map')
      .then(res => res.json())
      .then(data => setLocations(data.locations));
  }, []);
  
  return (
    <MapContainer center={[20, 0]} zoom={2} style={{ height: '600px' }}>
      <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
      {locations.map((loc, idx) => (
        <CircleMarker
          key={idx}
          center={[loc.latitude, loc.longitude]}
          radius={Math.log(loc.event_count + 1) * 3}
          fillColor="#dc2626"
          color="#dc2626"
        >
          <Popup>
            <strong>{loc.ip}</strong><br/>
            {loc.city}, {loc.country}<br/>
            Events: {loc.event_count}
          </Popup>
        </CircleMarker>
      ))}
    </MapContainer>
  );
};
```

### Alternative: Use Local Database

For better performance with many requests:

1. Download GeoLite2-City.mmdb:
```bash
# Sign up at https://dev.maxmind.com/geoip/geolite2/
# Download GeoLite2-City.mmdb
wget "https://download.maxmind.com/..." -O GeoLite2-City.mmdb
```

2. Install geoip2:
```bash
pip install geoip2
```

3. Update `geolocation.py`:
```python
geo_service = IPGeolocation(use_api=False)
```

### Rate Limits

ip-api.com free tier limits:
- 45 requests per minute
- System caches results for 24 hours
- Private IPs not queried

For production with high volume, consider:
- MaxMind GeoIP2 Precision API (paid)
- ipstack.com (paid)
- Local GeoLite2 database (free, no limits)

---

## 🚀 Quick Start with All Features

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements_enhanced.txt
```

### 2. Configure Notifications

Edit `backend/notifications.py` with your credentials.

### 3. Start Enhanced Backend

```bash
python main_enhanced.py
```

### 4. Login

```bash
curl -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Save the token!

### 5. Generate Sample Data

```bash
python sample_log_generator.py --mode full
```

### 6. View Incidents

```bash
curl http://localhost:8001/api/incidents
```

You'll see incidents were automatically created and alerts sent!

### 7. Export Data

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8001/api/events/export/csv -o events.csv
```

### 8. View Geographic Map

```bash
curl http://localhost:8001/api/geo/map
```

---

## 📝 Summary of New Endpoints

| Endpoint | Method | Auth Required | Description |
|----------|--------|---------------|-------------|
| /api/auth/register | POST | No | Register new user |
| /api/auth/login | POST | No | Login and get token |
| /api/auth/me | GET | Yes | Get current user info |
| /api/events/export/csv | GET | Yes | Export events to CSV |
| /api/geo/lookup/{ip} | GET | No | Lookup IP location |
| /api/geo/map | GET | No | Get map data |
| /api/incidents/{id}/alert | POST | Yes (analyst) | Manually trigger alert |

---

## ⚠️ Security Notes

1. **Change default password** immediately!
2. **Use HTTPS** in production
3. **Store secrets** in environment variables, not code
4. **Rotate JWT secret key** regularly
5. **Enable rate limiting** on authentication endpoints
6. **Use strong passwords** (min 12 characters)
7. **Monitor failed login attempts**

---

## 🎯 What's Complete Now

✅ **Authentication**: JWT tokens, RBAC, user management
✅ **Authorization**: Role-based endpoint protection
✅ **Email Alerts**: HTML/text emails via SMTP
✅ **Slack Alerts**: Rich formatting with webhooks
✅ **Webhook Alerts**: Generic JSON payloads
✅ **CSV Export**: Filtered exports up to 50K events
✅ **IP Geolocation**: Free API-based lookup
✅ **Geographic Maps**: Map data endpoint for visualization
✅ **Automatic Alerting**: Incidents trigger notifications
✅ **Manual Alerting**: Analysts can send custom alerts

You now have a **production-ready SIEM** with enterprise features! 🎉
