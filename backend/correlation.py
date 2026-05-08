from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
from sqlalchemy.orm import Session
from models import SecurityEvent, CorrelationRule, Incident, IncidentEvent
import logging

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Event correlation engine for detecting security incidents"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.event_cache = defaultdict(list)  # Cache recent events for correlation
        
    def process_event(self, event: SecurityEvent) -> List[Incident]:
        """Process a new event and check all correlation rules"""
        incidents = []
        
        # Get all enabled rules
        rules = self.db.query(CorrelationRule).filter(
            CorrelationRule.enabled == 'true'
        ).all()
        
        for rule in rules:
            try:
                incident = self._apply_rule(event, rule)
                if incident:
                    incidents.append(incident)
            except Exception as e:
                logger.error(f"Error applying rule {rule.name}: {e}")
        
        return incidents
    
    def _apply_rule(self, event: SecurityEvent, rule: CorrelationRule) -> Optional[Incident]:
        """Apply a correlation rule to an event"""
        conditions = rule.conditions
        
        if 'sequence' in conditions:
            return self._check_sequence_rule(event, rule, conditions)
        elif 'threshold' in conditions:
            return self._check_threshold_rule(event, rule, conditions)
        elif 'anomaly' in conditions:
            return self._check_anomaly_rule(event, rule, conditions)
        
        return None
    
    def _check_sequence_rule(self, event: SecurityEvent, rule: CorrelationRule, 
                            conditions: Dict[str, Any]) -> Optional[Incident]:
        """Check if event is part of a sequence pattern"""
        sequence = conditions['sequence']
        group_by = conditions.get('group_by', [])
        
        # Build grouping key
        group_key = tuple(getattr(event, field, None) for field in group_by)
        
        # Get recent events matching the grouping
        timeframe_start = event.timestamp - timedelta(seconds=rule.timeframe)
        
        query = self.db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= timeframe_start,
            SecurityEvent.timestamp <= event.timestamp
        )
        
        # Apply grouping filters
        for field in group_by:
            value = getattr(event, field, None)
            if value:
                query = query.filter(getattr(SecurityEvent, field) == value)
        
        recent_events = query.order_by(SecurityEvent.timestamp).all()
        
        # Check if sequence is matched
        sequence_index = 0
        matched_events = []
        
        for evt in recent_events:
            if sequence_index >= len(sequence):
                break
            
            step = sequence[sequence_index]
            
            # Check if event matches current step
            if self._event_matches_condition(evt, step):
                matched_events.append(evt)
                sequence_index += 1
        
        # If full sequence matched, create incident
        if sequence_index == len(sequence):
            return self._create_incident(rule, matched_events, event)
        
        return None
    
    def _check_threshold_rule(self, event: SecurityEvent, rule: CorrelationRule,
                             conditions: Dict[str, Any]) -> Optional[Incident]:
        """Check if event count exceeds threshold"""
        threshold_conditions = conditions['threshold']
        event_type = threshold_conditions.get('event_type')
        count_threshold = threshold_conditions.get('count', rule.threshold)
        group_by = conditions.get('group_by', [])
        
        # Get recent matching events
        timeframe_start = event.timestamp - timedelta(seconds=rule.timeframe)
        
        query = self.db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= timeframe_start,
            SecurityEvent.timestamp <= event.timestamp
        )
        
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        
        # Apply grouping filters
        for field in group_by:
            value = getattr(event, field, None)
            if value:
                query = query.filter(getattr(SecurityEvent, field) == value)
        
        event_count = query.count()
        
        # Check if threshold exceeded
        if event_count >= count_threshold:
            # Get all matching events for the incident
            matched_events = query.all()
            return self._create_incident(rule, matched_events, event)
        
        return None
    
    def _check_anomaly_rule(self, event: SecurityEvent, rule: CorrelationRule,
                           conditions: Dict[str, Any]) -> Optional[Incident]:
        """Check for anomalous behavior"""
        anomaly_conditions = conditions['anomaly']
        field = anomaly_conditions.get('field')
        threshold_multiplier = anomaly_conditions.get('threshold_multiplier', 3.0)
        baseline_days = anomaly_conditions.get('baseline_days', 7)
        
        # Calculate baseline
        baseline_start = event.timestamp - timedelta(days=baseline_days)
        baseline_end = event.timestamp - timedelta(hours=1)
        
        # Get baseline event count
        baseline_query = self.db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= baseline_start,
            SecurityEvent.timestamp <= baseline_end
        )
        
        if field:
            value = getattr(event, field, None)
            if value:
                baseline_query = baseline_query.filter(getattr(SecurityEvent, field) == value)
        
        baseline_count = baseline_query.count()
        baseline_rate = baseline_count / (baseline_days * 24) if baseline_days > 0 else 0
        
        # Get current rate (last hour)
        current_start = event.timestamp - timedelta(hours=1)
        current_query = self.db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= current_start,
            SecurityEvent.timestamp <= event.timestamp
        )
        
        if field:
            value = getattr(event, field, None)
            if value:
                current_query = current_query.filter(getattr(SecurityEvent, field) == value)
        
        current_count = current_query.count()
        
        # Check if current rate is anomalous
        if baseline_rate > 0 and current_count >= (baseline_rate * threshold_multiplier):
            matched_events = current_query.all()
            return self._create_incident(rule, matched_events, event)
        
        return None
    
    def _event_matches_condition(self, event: SecurityEvent, condition: Dict[str, Any]) -> bool:
        """Check if an event matches a condition"""
        for key, value in condition.items():
            if key in ['count', 'timeframe']:
                continue
            
            event_value = getattr(event, key, None)
            if event_value != value:
                return False
        
        return True
    
    def _create_incident(self, rule: CorrelationRule, matched_events: List[SecurityEvent],
                        trigger_event: SecurityEvent) -> Incident:
        """Create a new incident from matched events"""
        # Check if similar incident already exists (within last hour)
        recent_start = trigger_event.timestamp - timedelta(hours=1)
        
        existing = self.db.query(Incident).filter(
            Incident.rule_id == rule.id,
            Incident.last_seen >= recent_start,
            Incident.status.in_(['open', 'investigating'])
        )
        
        # Add grouping filters
        if trigger_event.source_ip:
            existing = existing.filter(Incident.source_ip == trigger_event.source_ip)
        if trigger_event.username:
            existing = existing.filter(Incident.username == trigger_event.username)
        
        existing_incident = existing.first()
        
        if existing_incident:
            # Update existing incident
            existing_incident.last_seen = trigger_event.timestamp
            existing_incident.event_count += len(matched_events)
            existing_incident.risk_score = max(existing_incident.risk_score, rule.risk_score)
            
            # Add new events to incident
            for event in matched_events:
                if event not in existing_incident.events:
                    existing_incident.events.append(event)
                    event.correlated = 'true'
            
            self.db.commit()
            return existing_incident
        
        # Create new incident
        incident = Incident(
            title=f"{rule.name} - {trigger_event.source_ip or trigger_event.username or 'Unknown'}",
            description=rule.description,
            severity=rule.severity,
            risk_score=rule.risk_score,
            rule_id=rule.id,
            source_ip=trigger_event.source_ip,
            username=trigger_event.username,
            hostname=trigger_event.hostname,
            first_seen=matched_events[0].timestamp if matched_events else trigger_event.timestamp,
            last_seen=trigger_event.timestamp,
            event_count=len(matched_events)
        )
        
        self.db.add(incident)
        self.db.flush()  # Get incident ID
        
        # Associate events with incident
        for event in matched_events:
            incident.events.append(event)
            event.correlated = 'true'
        
        self.db.commit()
        
        logger.info(f"Created incident: {incident.title} (ID: {incident.id})")
        return incident


def create_default_rules(db_session: Session):
    """Create default correlation rules"""
    default_rules = [
        {
            'name': 'Brute Force Attack',
            'description': 'Multiple failed login attempts followed by successful login',
            'severity': 'high',
            'conditions': {
                'sequence': [
                    {'event_type': 'failed_login', 'count': 5},
                    {'event_type': 'successful_login', 'count': 1}
                ],
                'group_by': ['source_ip', 'username']
            },
            'timeframe': 300,  # 5 minutes
            'risk_score': 80.0
        },
        {
            'name': 'Port Scan Detection',
            'description': 'High volume of connection attempts to different ports',
            'severity': 'medium',
            'conditions': {
                'threshold': {
                    'event_type': 'network_traffic',
                    'count': 20
                },
                'group_by': ['source_ip']
            },
            'timeframe': 60,  # 1 minute
            'risk_score': 60.0
        },
        {
            'name': 'Repeated Authentication Failures',
            'description': 'High number of failed login attempts',
            'severity': 'medium',
            'conditions': {
                'threshold': {
                    'event_type': 'failed_login',
                    'count': 10
                },
                'group_by': ['source_ip']
            },
            'timeframe': 600,  # 10 minutes
            'risk_score': 70.0
        },
        {
            'name': 'Web Attack Pattern',
            'description': 'Multiple HTTP attack attempts detected',
            'severity': 'high',
            'conditions': {
                'threshold': {
                    'event_type': 'http_attack_attempt',
                    'count': 3
                },
                'group_by': ['source_ip']
            },
            'timeframe': 300,
            'risk_score': 85.0
        },
        {
            'name': 'Malware Activity Spike',
            'description': 'Unusual spike in malware detections',
            'severity': 'critical',
            'conditions': {
                'anomaly': {
                    'field': 'event_type',
                    'threshold_multiplier': 5.0,
                    'baseline_days': 7
                }
            },
            'timeframe': 3600,
            'risk_score': 95.0
        }
    ]
    
    for rule_data in default_rules:
        existing = db_session.query(CorrelationRule).filter(
            CorrelationRule.name == rule_data['name']
        ).first()
        
        if not existing:
            rule = CorrelationRule(**rule_data)
            db_session.add(rule)
    
    db_session.commit()
