# SIEM Dashboard - Deployment Guide

## Quick Start (Development)

### 1. Start Backend

```bash
cd backend
pip install -r requirements.txt
python main_enhanced.py
```

Backend runs on `http://localhost:8001`

### 2. Test with Sample Data

```bash
# In a new terminal
cd backend
python sample_log_generator.py --mode full
```

### 3. Access API

Visit `http://localhost:8001/docs` for interactive API documentation (Swagger UI)

### 4. Integrate Frontend

The React component `SIEMDashboard.jsx` can be integrated into any React application:

```javascript
import SIEMDashboard from './SIEMDashboard';

function App() {
  return <SIEMDashboard />;
}
```

## Production Deployment

### Backend (FastAPI)

#### Option 1: Uvicorn + Systemd

Create `/etc/systemd/system/siem-backend.service`:

```ini
[Unit]
Description=SIEM Dashboard Backend
After=network.target

[Service]
Type=simple
User=siem
WorkingDirectory=/opt/siem-dashboard/backend
Environment="PATH=/opt/siem-dashboard/venv/bin"
ExecStart=/opt/siem-dashboard/venv/bin/uvicorn main_enhanced:app --host 0.0.0.0 --port 8001 --workers 4

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable siem-backend
sudo systemctl start siem-backend
```

#### Option 2: Docker

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main_enhanced:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

Build and run:

```bash
docker build -t siem-backend .
docker run -p 8000:8000 -v /opt/siem-data:/app/data siem-backend
```

#### Option 3: Gunicorn + Nginx

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn main_enhanced:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

Nginx configuration:

```nginx
server {
    listen 80;
    server_name siem.company.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Frontend (React)

#### Build for Production

```bash
cd frontend
npm run build
```

Serve with nginx:

```nginx
server {
    listen 80;
    server_name siem-dashboard.company.com;
    
    root /var/www/siem-dashboard/build;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://127.0.0.1:8000/api;
    }
}
```

### Database Migration

For production, migrate from SQLite to PostgreSQL:

```bash
# Install PostgreSQL driver
pip install psycopg2-binary

# Update main.py
DATABASE_URL = "postgresql://siem:password@localhost/siem_db"
```

### Log Ingestion Configuration

#### Configure Syslog Sources

On network devices, configure syslog forwarding:

**Cisco Router/Switch**:
```
logging host <SIEM-IP> transport udp port 5514
```

**Linux (rsyslog)**:
```
# /etc/rsyslog.conf
*.* @<SIEM-IP>:5514
```

**Windows (NXLog)**:
```xml
<Output syslog>
    Module om_tcp
    Host <SIEM-IP>
    Port 5515
</Output>
```

#### Monitor Log Files

Update `main.py` to add file monitors:

```python
# On startup
ingestion_manager.add_file_monitor([
    '/var/log/auth.log',
    '/var/log/apache2/access.log',
    '/var/log/firewall.log'
], parser_format='auto')
```

### High Availability

#### Load Balancing

Use HAProxy to distribute load:

```
frontend siem_api
    bind *:8000
    default_backend siem_servers

backend siem_servers
    balance roundrobin
    server siem1 10.0.0.10:8000 check
    server siem2 10.0.0.11:8000 check
    server siem3 10.0.0.12:8000 check
```

#### Database Replication

PostgreSQL streaming replication:

```bash
# Primary server
wal_level = replica
max_wal_senders = 3

# Standby server
standby_mode = on
primary_conninfo = 'host=primary-db port=5432 user=replicator'
```

### Security Hardening

#### Enable Authentication

Add to `main.py`:

```python
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext

security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    # Implement authentication logic
    pass

@app.get("/api/events", dependencies=[Depends(verify_credentials)])
async def get_events(...):
    ...
```

#### HTTPS/TLS

Configure nginx with SSL:

```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/siem.crt;
    ssl_certificate_key /etc/ssl/private/siem.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
}
```

#### Firewall Rules

```bash
# Allow only necessary ports
ufw allow 443/tcp   # HTTPS
ufw allow 5514/udp  # Syslog UDP
ufw allow 5515/tcp  # Syslog TCP
ufw enable
```

### Monitoring & Maintenance

#### Health Checks

Add endpoint to `main.py`:

```python
@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        return {"status": "healthy"}
    except:
        return {"status": "unhealthy"}, 500
```

#### Log Rotation

Configure logrotate:

```
/var/log/siem/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 siem siem
    postrotate
        systemctl reload siem-backend
    endscript
}
```

#### Database Maintenance

Regular cleanup:

```sql
-- Archive old events (older than 90 days)
DELETE FROM security_events 
WHERE timestamp < NOW() - INTERVAL '90 days';

-- Vacuum database
VACUUM ANALYZE;
```

Automated script:

```bash
#!/bin/bash
# /opt/siem-dashboard/scripts/cleanup.sh

psql -U siem siem_db << EOF
DELETE FROM security_events WHERE timestamp < NOW() - INTERVAL '90 days';
VACUUM ANALYZE;
EOF
```

Add to crontab:

```
0 2 * * 0 /opt/siem-dashboard/scripts/cleanup.sh
```

### Performance Tuning

#### PostgreSQL

```ini
# postgresql.conf
shared_buffers = 4GB
effective_cache_size = 12GB
work_mem = 64MB
maintenance_work_mem = 1GB
max_connections = 200

# Indexes
CREATE INDEX idx_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX idx_events_source_ip ON security_events(source_ip);
CREATE INDEX idx_events_severity ON security_events(severity);
```

#### FastAPI Workers

```bash
# Calculate optimal workers
workers = (2 * CPU_cores) + 1

# Example for 4-core system
uvicorn main_enhanced:app --workers 9
```

#### Caching

Add Redis for caching:

```python
import redis
from functools import wraps

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def cache_result(timeout=300):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
            
            result = await func(*args, **kwargs)
            redis_client.setex(cache_key, timeout, json.dumps(result))
            return result
        return wrapper
    return decorator

@app.get("/api/events/stats/summary")
@cache_result(timeout=60)
async def get_event_summary(...):
    ...
```

### Backup Strategy

#### Database Backups

```bash
#!/bin/bash
# /opt/siem-dashboard/scripts/backup.sh

BACKUP_DIR="/backups/siem"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup database
pg_dump -U siem siem_db | gzip > "$BACKUP_DIR/siem_db_$DATE.sql.gz"

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" /opt/siem-dashboard/backend/*.py

# Keep only last 30 days
find $BACKUP_DIR -type f -mtime +30 -delete
```

Schedule daily backups:

```
0 1 * * * /opt/siem-dashboard/scripts/backup.sh
```

### Disaster Recovery

1. **Regular backups**: Database + configuration
2. **Documentation**: Deployment procedures
3. **Testing**: Restore backups quarterly
4. **Redundancy**: Multiple SIEM instances
5. **Monitoring**: Alert on system failures

### Troubleshooting

#### Common Issues

**Problem**: Syslog not receiving logs
```bash
# Check if port is open
netstat -uln | grep 5514

# Check firewall
ufw status

# Test with logger
logger -n localhost -P 5514 "Test message"
```

**Problem**: High memory usage
```bash
# Check database connections
psql -U siem -c "SELECT count(*) FROM pg_stat_activity;"

# Adjust worker count
# Reduce workers in systemd service file
```

**Problem**: Slow queries
```bash
# Enable query logging
log_statement = 'all'
log_duration = on

# Check slow queries
psql -U siem -c "SELECT query, calls, total_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

#### Debug Mode

Enable verbose logging:

```python
# main.py
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/siem/debug.log'),
        logging.StreamHandler()
    ]
)
```

### Scaling Considerations

**Events/Second Capacity**:
- Single instance: ~1,000 events/sec
- With PostgreSQL: ~5,000 events/sec
- Clustered: 10,000+ events/sec

**Storage Requirements**:
- Average event size: ~2KB
- 1 million events/day: ~2GB/day
- 30-day retention: ~60GB

**Recommended Hardware**:
- Small (< 10K events/day): 2 CPU, 4GB RAM
- Medium (< 100K events/day): 4 CPU, 16GB RAM
- Large (< 1M events/day): 8+ CPU, 32GB+ RAM

### Compliance & Auditing

#### Enable Audit Logging

```python
@app.middleware("http")
async def audit_log(request: Request, call_next):
    logger.info(f"API call: {request.method} {request.url} from {request.client.host}")
    response = await call_next(request)
    return response
```

#### Data Retention Policies

Implement tiered storage:

1. **Hot storage** (0-30 days): Full events in PostgreSQL
2. **Warm storage** (30-90 days): Compressed events
3. **Cold storage** (90+ days): Archived to S3/tape
4. **Deletion** (> retention period): Securely delete

---

For additional support, consult the main README.md documentation.
