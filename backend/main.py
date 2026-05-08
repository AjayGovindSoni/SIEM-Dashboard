from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import create_engine, func, and_, or_
from sqlalchemy.orm import Session, sessionmaker
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import logging
import io
import csv
import os
from dotenv import load_dotenv

# Load .env file (must be in same directory as this script)
load_dotenv()

from models import Base, SecurityEvent, CorrelationRule, Incident, Alert
from log_parser import LogParserFactory
from correlation import CorrelationEngine, create_default_rules
from syslog_receiver import LogIngestionManager

# Import new modules
from auth import (
    User, APIKey, Token, UserCreate, UserLogin, TokenData,
    authenticate_user, create_access_token, get_current_user,
    get_current_user_from_token, require_role, create_default_admin,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from notifications import AlertNotificationManager, AlertNotificationConfig
from geolocation import geo_service



from db import get_db, SessionLocal, engine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
#DATABASE_URL = "sqlite:///./siem.db"
#engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
#SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(title="SIEM Dashboard API", version="2.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global managers
ingestion_manager = None
notification_manager = AlertNotificationManager()


# Dependency
#def get_db():
#    db = SessionLocal()
#    try:
#        yield db
#    finally:
#        db.close()


# Pydantic models
class EventCreate(BaseModel):
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    event_type: str
    severity: str
    category: str
    message: str
    raw_log: Optional[str] = None
    event_metadata: Optional[Dict[str, Any]] = None


class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    severity: str
    conditions: Dict[str, Any]
    timeframe: int = 300
    threshold: int = 1
    risk_score: float = 50.0


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class AlertConfig(BaseModel):
    methods: Optional[List[str]] = None
    recipients: Optional[List[str]] = None


# Event handlers
def handle_parsed_event(event_data: Dict[str, Any]):
    """Handle a parsed event from ingestion"""
    db = SessionLocal()
    try:
        # Create event
        event = SecurityEvent(
            timestamp=event_data.get('timestamp', datetime.now()),
            source_ip=event_data.get('source_ip'),
            destination_ip=event_data.get('destination_ip'),
            source_port=event_data.get('source_port'),
            destination_port=event_data.get('destination_port'),
            username=event_data.get('username'),
            hostname=event_data.get('hostname'),
            event_type=event_data.get('event_type', 'unknown'),
            severity=event_data.get('severity', 'info'),
            category=event_data.get('category', 'unknown'),
            message=event_data.get('message', ''),
            raw_log=event_data.get('raw_log', ''),
            event_metadata=event_data.get('event_metadata', {})
        )
        
        db.add(event)
        db.commit()
        db.refresh(event)
        
        # Run correlation
        correlation_engine = CorrelationEngine(db)
        incidents = correlation_engine.process_event(event)
        
        # Send alerts for new incidents
        for incident in incidents:
            logger.info(f"Incident created: {incident.title}")
            # Send notifications in background
            try:
                notification_manager.send_alert(incident, db)
            except Exception as e:
                logger.error(f"Failed to send alert for incident {incident.id}: {e}")
        
    except Exception as e:
        logger.error(f"Error handling event: {e}")
        db.rollback()
    finally:
        db.close()


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize database and start ingestion"""
    global ingestion_manager
    
    # Create default admin user
    db = SessionLocal()
    create_default_admin(db)
    create_default_rules(db)
    db.close()
    
    # Start ingestion manager
    ingestion_manager = LogIngestionManager(event_callback=handle_parsed_event)
    
    # Start syslog receiver
    try:
        ingestion_manager.start_syslog_receiver(udp_port=5514, tcp_port=5515)
        logger.info("Log ingestion started")
    except Exception as e:
        logger.error(f"Failed to start log ingestion: {e}")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Stop ingestion"""
    if ingestion_manager:
        ingestion_manager.stop_all()


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.post("/api/auth/register", response_model=Token)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user (admin only in production)"""
    from auth import get_password_hash
    
    # Check if username exists
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password),
        role=user.role
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Create token
    access_token = create_access_token(
        data={"sub": db_user.username, "role": db_user.role}
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/auth/login", response_model=Token)
async def login(user_login: UserLogin, db: Session = Depends(get_db)):
    """Login and get access token"""
    user = authenticate_user(db, user_login.username, user_login.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active
    }


# ============================================================================
# EVENT ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """API root"""
    return {
        "name": "SIEM Dashboard API",
        "version": "2.0.0",
        "status": "running",
        "features": ["authentication", "notifications", "geolocation", "csv_export"]
    }


@app.post("/api/events")
async def create_event(
    event: EventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new security event (requires authentication)"""
    timestamp = datetime.fromisoformat(event.timestamp.replace("Z", "")) if event.timestamp else datetime.now()
    
    db_event = SecurityEvent(
        timestamp=timestamp,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        username=event.username,
        hostname=event.hostname,
        event_type=event.event_type,
        severity=event.severity,
        category=event.category,
        message=event.message,
        raw_log=event.raw_log or event.message,
        event_metadata=event.event_metadata or {}
    )
    
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    # Run correlation
    correlation_engine = CorrelationEngine(db)
    correlation_engine.process_event(db_event)
    
    return db_event.to_dict()


@app.get("/api/events")
async def get_events(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Query security events (public endpoint for dashboard)"""
    query = db.query(SecurityEvent)
    
    # Apply filters
    if start_time:
        query = query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    if end_time:
        query = query.filter(SecurityEvent.timestamp <= datetime.fromisoformat(end_time.replace("Z", "")))
    if source_ip:
        query = query.filter(SecurityEvent.source_ip == source_ip)
    if username:
        query = query.filter(SecurityEvent.username == username)
    if hostname:
        query = query.filter(SecurityEvent.hostname == hostname)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if category:
        query = query.filter(SecurityEvent.category == category)
    if search:
        query = query.filter(SecurityEvent.message.contains(search))
    
    # Get total count
    total = query.count()
    
    # Get paginated results
    events = query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [event.to_dict() for event in events]
    }


@app.get("/api/events/export/csv")
async def export_events_csv(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(10000, le=50000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export events to CSV (requires authentication)"""
    query = db.query(SecurityEvent)
    
    # Apply filters
    if start_time:
        query = query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    if end_time:
        query = query.filter(SecurityEvent.timestamp <= datetime.fromisoformat(end_time.replace("Z", "")))
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    
    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Timestamp', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port',
        'Username', 'Hostname', 'Event Type', 'Severity', 'Category', 'Message', 'Risk Score', 'Correlated'
    ])
    
    # Write data
    for event in events:
        writer.writerow([
            event.id,
            event.timestamp.isoformat() if event.timestamp else '',
            event.source_ip or '',
            event.destination_ip or '',
            event.source_port or '',
            event.destination_port or '',
            event.username or '',
            event.hostname or '',
            event.event_type,
            event.severity,
            event.category,
            event.message,
            event.risk_score,
            event.correlated
        ])
    
    # Return as downloadable file
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=siem_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )


# NOTE: /stats/summary and /stats/timeline MUST be defined before /{event_id}
# so FastAPI does not incorrectly match "stats" as the event_id path parameter.

@app.get("/api/events/stats/summary")
async def get_event_summary(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get event statistics summary"""
    query = db.query(SecurityEvent)
    
    if start_time:
        query = query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    if end_time:
        query = query.filter(SecurityEvent.timestamp <= datetime.fromisoformat(end_time.replace("Z", "")))
    
    # Total events
    total_events = query.count()
    
    # By severity
    by_severity_query = db.query(
        SecurityEvent.severity,
        func.count(SecurityEvent.id)
    )
    if start_time:
        by_severity_query = by_severity_query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    if end_time:
        by_severity_query = by_severity_query.filter(SecurityEvent.timestamp <= datetime.fromisoformat(end_time.replace("Z", "")))
    by_severity = by_severity_query.group_by(SecurityEvent.severity).all()
    
    # By category
    by_category_query = db.query(
        SecurityEvent.category,
        func.count(SecurityEvent.id)
    )
    if start_time:
        by_category_query = by_category_query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    if end_time:
        by_category_query = by_category_query.filter(SecurityEvent.timestamp <= datetime.fromisoformat(end_time.replace("Z", "")))
    by_category = by_category_query.group_by(SecurityEvent.category).all()
    
    # By event type
    by_type_query = db.query(
        SecurityEvent.event_type,
        func.count(SecurityEvent.id)
    )
    if start_time:
        by_type_query = by_type_query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    if end_time:
        by_type_query = by_type_query.filter(SecurityEvent.timestamp <= datetime.fromisoformat(end_time.replace("Z", "")))
    by_type = by_type_query.group_by(SecurityEvent.event_type).order_by(func.count(SecurityEvent.id).desc()).limit(10).all()
    
    return {
        "total_events": total_events,
        "by_severity": {sev: count for sev, count in by_severity},
        "by_category": {cat: count for cat, count in by_category},
        "top_event_types": {evt: count for evt, count in by_type}
    }


@app.get("/api/events/stats/timeline")
async def get_event_timeline(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    interval: str = "hour",
    db: Session = Depends(get_db)
):
    """Get event timeline"""
    if not end_time:
        end_time = datetime.now().isoformat()
    if not start_time:
        start_time = (datetime.now() - timedelta(days=1)).isoformat()
    
    start_dt = datetime.fromisoformat(start_time.replace("Z", ""))
    end_dt = datetime.fromisoformat(end_time.replace("Z", ""))
    
    events = db.query(SecurityEvent).filter(
        and_(
            SecurityEvent.timestamp >= start_dt,
            SecurityEvent.timestamp <= end_dt
        )
    ).all()
    
    timeline = {}
    for event in events:
        if interval == "hour":
            key = event.timestamp.strftime("%Y-%m-%d %H:00")
        elif interval == "day":
            key = event.timestamp.strftime("%Y-%m-%d")
        elif interval == "minute":
            key = event.timestamp.strftime("%Y-%m-%d %H:%M")
        else:
            key = event.timestamp.strftime("%Y-%m-%d %H:00")
        
        if key not in timeline:
            timeline[key] = 0
        timeline[key] += 1
    
    return {"timeline": timeline}


@app.get("/api/events/{event_id}")
async def get_event(event_id: int, db: Session = Depends(get_db)):
    """Get a specific event"""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event.to_dict()


# ============================================================================
# GEOLOCATION ENDPOINTS
# ============================================================================

@app.get("/api/geo/lookup/{ip_address}")
async def lookup_ip_location(ip_address: str):
    """Get geographic location for an IP address"""
    location = geo_service.get_location(ip_address)
    if not location:
        raise HTTPException(status_code=404, detail="Location not found for IP")
    return location


@app.get("/api/geo/map")
async def get_geo_map_data(
    start_time: Optional[str] = None,
    limit: int = Query(1000, le=5000),
    db: Session = Depends(get_db)
):
    """Get geographic map data for events"""
    query = db.query(SecurityEvent).filter(SecurityEvent.source_ip.isnot(None))
    
    if start_time:
        query = query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    
    events = query.limit(limit).all()
    
    # Get unique IPs
    unique_ips = list(set([e.source_ip for e in events if e.source_ip]))
    
    # Get locations
    locations = geo_service.get_batch_locations(unique_ips)
    
    # Count events per location
    map_data = []
    for ip, location in locations.items():
        event_count = sum(1 for e in events if e.source_ip == ip)
        map_data.append({
            **location,
            'event_count': event_count
        })
    
    return {"locations": map_data}


# ============================================================================
# INCIDENT ENDPOINTS
# ============================================================================

@app.get("/api/incidents")
async def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Get security incidents"""
    query = db.query(Incident)
    
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    
    total = query.count()
    incidents = query.order_by(Incident.last_seen.desc()).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "incidents": [incident.to_dict() for incident in incidents]
    }


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Get incident details"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    result = incident.to_dict()
    result['events'] = [event.to_dict() for event in incident.events]
    return result


@app.patch("/api/incidents/{incident_id}")
async def update_incident(
    incident_id: int,
    update: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update incident (requires authentication)"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if update.status:
        incident.status = update.status
    if update.assigned_to:
        incident.assigned_to = update.assigned_to
    if update.notes:
        incident.notes = update.notes
    
    db.commit()
    return incident.to_dict()


@app.post("/api/incidents/{incident_id}/alert")
async def send_incident_alert(
    incident_id: int,
    alert_config: AlertConfig,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("analyst"))
):
    """Manually trigger alert for incident (requires analyst role)"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Send alert in background
    def send_alert():
        notification_manager.send_alert(
            incident,
            db,
            methods=alert_config.methods,
            recipients=alert_config.recipients
        )
    
    background_tasks.add_task(send_alert)
    
    return {"status": "alert_queued", "incident_id": incident_id}


# ============================================================================
# RULE ENDPOINTS
# ============================================================================

@app.get("/api/rules")
async def get_rules(db: Session = Depends(get_db)):
    """Get correlation rules"""
    rules = db.query(CorrelationRule).all()
    return [rule.to_dict() for rule in rules]


@app.post("/api/rules")
async def create_rule(
    rule: RuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))
):
    """Create correlation rule (requires admin role)"""
    db_rule = CorrelationRule(
        name=rule.name,
        description=rule.description,
        enabled='true' if rule.enabled else 'false',
        severity=rule.severity,
        conditions=rule.conditions,
        timeframe=rule.timeframe,
        threshold=rule.threshold,
        risk_score=rule.risk_score
    )
    
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    
    return db_rule.to_dict()


# ============================================================================
# STATS ENDPOINTS
# ============================================================================

@app.get("/api/stats/top-sources")
async def get_top_sources(
    limit: int = 10,
    start_time: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get top source IPs"""
    query = db.query(
        SecurityEvent.source_ip,
        func.count(SecurityEvent.id).label('count')
    ).filter(SecurityEvent.source_ip.isnot(None))
    
    if start_time:
        query = query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time.replace("Z", "")))
    
    results = query.group_by(SecurityEvent.source_ip).order_by(
        func.count(SecurityEvent.id).desc()
    ).limit(limit).all()
    
    return [{"source_ip": ip, "count": count} for ip, count in results]


if __name__ == "__main__":
    import uvicorn
    api_port = int(os.getenv("API_PORT", "8001"))
    api_host = os.getenv("API_HOST", "0.0.0.0")
    uvicorn.run(app, host=api_host, port=api_port)
