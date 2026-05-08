from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class SecurityEvent(Base):
    """Normalized security event model"""
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), index=True)  # IPv4/IPv6
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    username = Column(String(255), index=True)
    hostname = Column(String(255), index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    category = Column(String(50), index=True)  # authentication, network, malware, etc.
    message = Column(Text)
    raw_log = Column(Text)
    event_metadata = Column(JSON)  # Additional fields from original log
    risk_score = Column(Float, default=0.0)
    correlated = Column(String(10), default='false')  # 'true' or 'false' for indexing
    
    # Relationship to incidents
    incidents = relationship("Incident", secondary="incident_events", back_populates="events")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'username': self.username,
            'hostname': self.hostname,
            'event_type': self.event_type,
            'severity': self.severity,
            'category': self.category,
            'message': self.message,
            'raw_log': self.raw_log,
            'event_metadata': self.event_metadata,
            'risk_score': self.risk_score,
            'correlated': self.correlated
        }


class CorrelationRule(Base):
    """Event correlation rule definition"""
    __tablename__ = 'correlation_rules'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    enabled = Column(String(10), default='true')
    severity = Column(String(20), nullable=False)
    
    # Rule conditions (JSON format)
    conditions = Column(JSON, nullable=False)
    # Example: {
    #   "sequence": [
    #     {"event_type": "failed_login", "count": 5, "timeframe": 300},
    #     {"event_type": "successful_login", "count": 1, "timeframe": 60}
    #   ],
    #   "group_by": ["source_ip", "username"]
    # }
    
    timeframe = Column(Integer, default=300)  # seconds
    threshold = Column(Integer, default=1)
    risk_score = Column(Float, default=50.0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'severity': self.severity,
            'conditions': self.conditions,
            'timeframe': self.timeframe,
            'threshold': self.threshold,
            'risk_score': self.risk_score,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class Incident(Base):
    """Security incident detected by correlation"""
    __tablename__ = 'incidents'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default='open')  # open, investigating, resolved, false_positive
    risk_score = Column(Float, default=0.0)
    
    rule_id = Column(Integer, ForeignKey('correlation_rules.id'))
    rule = relationship("CorrelationRule")
    
    source_ip = Column(String(45))
    username = Column(String(255))
    hostname = Column(String(255))
    
    first_seen = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=False)
    event_count = Column(Integer, default=0)
    
    assigned_to = Column(String(255))
    notes = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to events
    events = relationship("SecurityEvent", secondary="incident_events", back_populates="incidents")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'risk_score': self.risk_score,
            'rule_id': self.rule_id,
            'source_ip': self.source_ip,
            'username': self.username,
            'hostname': self.hostname,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'event_count': self.event_count,
            'assigned_to': self.assigned_to,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class IncidentEvent(Base):
    """Association table between incidents and events"""
    __tablename__ = 'incident_events'
    
    incident_id = Column(Integer, ForeignKey('incidents.id'), primary_key=True)
    event_id = Column(Integer, ForeignKey('security_events.id'), primary_key=True)


class Alert(Base):
    """Alert notifications"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey('incidents.id'))
    incident = relationship("Incident")
    
    alert_type = Column(String(50))  # email, slack, webhook
    status = Column(String(20), default='pending')  # pending, sent, failed
    recipient = Column(String(255))
    
    sent_at = Column(DateTime)
    error_message = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'incident_id': self.incident_id,
            'alert_type': self.alert_type,
            'status': self.status,
            'recipient': self.recipient,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
