# Example Correlation Rules for SIEM Dashboard

This document provides example correlation rules for detecting various security threats.

## Rule Format

```json
{
    "name": "Rule Name",
    "description": "What this rule detects",
    "enabled": true,
    "severity": "critical|high|medium|low",
    "conditions": {
        // Rule conditions (see types below)
    },
    "timeframe": 300,  // seconds
    "threshold": 1,
    "risk_score": 75.0
}
```

## Rule Types

### 1. Sequence Rules

Detect ordered sequences of events.

#### Brute Force Detection
```json
{
    "name": "SSH Brute Force Attack",
    "description": "Multiple failed SSH login attempts followed by successful login",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "sequence": [
            {"event_type": "failed_login", "count": 5},
            {"event_type": "successful_login", "count": 1}
        ],
        "group_by": ["source_ip", "username"]
    },
    "timeframe": 300,
    "risk_score": 80.0
}
```

#### Credential Stuffing
```json
{
    "name": "Credential Stuffing Attack",
    "description": "Failed login attempts across multiple usernames from same IP",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "sequence": [
            {"event_type": "failed_login", "count": 10}
        ],
        "group_by": ["source_ip"]
    },
    "timeframe": 600,
    "risk_score": 75.0
}
```

### 2. Threshold Rules

Alert when event count exceeds threshold.

#### Port Scan Detection
```json
{
    "name": "Network Port Scan",
    "description": "Rapid connection attempts to multiple ports",
    "enabled": true,
    "severity": "medium",
    "conditions": {
        "threshold": {
            "event_type": "network_traffic",
            "count": 20
        },
        "group_by": ["source_ip"]
    },
    "timeframe": 60,
    "risk_score": 60.0
}
```

#### DDoS Detection
```json
{
    "name": "Potential DDoS Attack",
    "description": "Abnormally high connection rate",
    "enabled": true,
    "severity": "critical",
    "conditions": {
        "threshold": {
            "event_type": "network_traffic",
            "count": 1000
        },
        "group_by": ["destination_ip"]
    },
    "timeframe": 60,
    "risk_score": 95.0
}
```

#### Failed Firewall Rules
```json
{
    "name": "Repeated Firewall Blocks",
    "description": "Multiple blocked connection attempts",
    "enabled": true,
    "severity": "medium",
    "conditions": {
        "threshold": {
            "event_type": "network_blocked",
            "count": 50
        },
        "group_by": ["source_ip"]
    },
    "timeframe": 300,
    "risk_score": 55.0
}
```

### 3. Anomaly Rules

Detect deviations from baseline behavior.

#### Traffic Spike
```json
{
    "name": "Abnormal Traffic Volume",
    "description": "Traffic volume significantly above baseline",
    "enabled": true,
    "severity": "medium",
    "conditions": {
        "anomaly": {
            "field": "source_ip",
            "threshold_multiplier": 5.0,
            "baseline_days": 7
        }
    },
    "timeframe": 3600,
    "risk_score": 60.0
}
```

#### Unusual Login Time
```json
{
    "name": "Off-Hours Authentication",
    "description": "Login attempts during unusual hours",
    "enabled": true,
    "severity": "low",
    "conditions": {
        "threshold": {
            "event_type": "successful_login",
            "count": 1
        },
        "group_by": ["username"],
        "time_constraint": {
            "hours": [0, 1, 2, 3, 4, 5]  // 12am-6am
        }
    },
    "timeframe": 3600,
    "risk_score": 40.0
}
```

## Web Application Rules

#### SQL Injection Attempt
```json
{
    "name": "SQL Injection Detected",
    "description": "SQL injection patterns in HTTP requests",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "threshold": {
            "event_type": "http_attack_attempt",
            "count": 1
        },
        "pattern_match": {
            "message": "(?i)(union|select|insert|update|delete|drop).*from"
        }
    },
    "timeframe": 60,
    "risk_score": 85.0
}
```

#### Directory Traversal
```json
{
    "name": "Directory Traversal Attack",
    "description": "Attempts to access files outside web root",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "threshold": {
            "event_type": "http_request",
            "count": 3
        },
        "pattern_match": {
            "message": "\\.\\./|\\.\\.\\\\"
        },
        "group_by": ["source_ip"]
    },
    "timeframe": 300,
    "risk_score": 80.0
}
```

#### XSS Attack
```json
{
    "name": "Cross-Site Scripting Attempt",
    "description": "XSS attack patterns detected",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "threshold": {
            "event_type": "http_request",
            "count": 2
        },
        "pattern_match": {
            "message": "(?i)<script|javascript:|onerror=|onload="
        },
        "group_by": ["source_ip"]
    },
    "timeframe": 300,
    "risk_score": 75.0
}
```

## Malware & Intrusion Rules

#### Ransomware Activity
```json
{
    "name": "Potential Ransomware",
    "description": "Ransomware indicators detected",
    "enabled": true,
    "severity": "critical",
    "conditions": {
        "threshold": {
            "event_type": "malware_detection",
            "count": 1
        },
        "pattern_match": {
            "message": "(?i)(ransom|crypto|locky|wannacry|petya)"
        }
    },
    "timeframe": 60,
    "risk_score": 100.0
}
```

#### Lateral Movement
```json
{
    "name": "Lateral Movement Detected",
    "description": "Successful logins to multiple systems in short time",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "sequence": [
            {"event_type": "successful_login", "count": 5}
        ],
        "group_by": ["username"],
        "unique_count": {
            "field": "hostname",
            "minimum": 3
        }
    },
    "timeframe": 600,
    "risk_score": 85.0
}
```

#### Beacon Detection
```json
{
    "name": "C2 Beacon Activity",
    "description": "Regular outbound connections (potential C2 communication)",
    "enabled": true,
    "severity": "critical",
    "conditions": {
        "threshold": {
            "event_type": "network_traffic",
            "count": 10
        },
        "group_by": ["source_ip", "destination_ip"],
        "pattern": "regular_interval",
        "interval_seconds": 60
    },
    "timeframe": 3600,
    "risk_score": 90.0
}
```

## Privilege Escalation Rules

#### Sudo Abuse
```json
{
    "name": "Excessive Sudo Usage",
    "description": "Unusual number of sudo commands",
    "enabled": true,
    "severity": "medium",
    "conditions": {
        "threshold": {
            "event_type": "privilege_escalation",
            "count": 10
        },
        "group_by": ["username"]
    },
    "timeframe": 300,
    "risk_score": 65.0
}
```

#### Administrator Account Creation
```json
{
    "name": "Privileged Account Created",
    "description": "New administrator or root-level account created",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "threshold": {
            "event_type": "account_created",
            "count": 1
        },
        "pattern_match": {
            "metadata.group": "(?i)(admin|root|wheel|sudo)"
        }
    },
    "timeframe": 60,
    "risk_score": 80.0
}
```

## Data Exfiltration Rules

#### Large Data Transfer
```json
{
    "name": "Suspicious Data Transfer",
    "description": "Unusually large outbound data transfer",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "threshold": {
            "event_type": "data_transfer",
            "count": 1
        },
        "value_threshold": {
            "field": "metadata.bytes",
            "operator": ">",
            "value": 1073741824  // 1GB
        },
        "group_by": ["source_ip"]
    },
    "timeframe": 3600,
    "risk_score": 75.0
}
```

#### Database Export
```json
{
    "name": "Database Export Detected",
    "description": "Large database query or export operation",
    "enabled": true,
    "severity": "medium",
    "conditions": {
        "threshold": {
            "event_type": "database_query",
            "count": 1
        },
        "pattern_match": {
            "message": "(?i)(mysqldump|pg_dump|backup|export)"
        },
        "group_by": ["username"]
    },
    "timeframe": 300,
    "risk_score": 70.0
}
```

## Compliance Rules

#### PCI-DSS: Failed Access to Cardholder Data
```json
{
    "name": "Unauthorized Cardholder Data Access",
    "description": "Failed attempts to access cardholder data environment",
    "enabled": true,
    "severity": "high",
    "conditions": {
        "threshold": {
            "category": "authentication",
            "count": 3
        },
        "pattern_match": {
            "metadata.resource": "(?i)(payment|card|pci)"
        },
        "group_by": ["username"]
    },
    "timeframe": 900,
    "risk_score": 80.0
}
```

#### HIPAA: PHI Access After Hours
```json
{
    "name": "Off-Hours PHI Access",
    "description": "Access to protected health information outside business hours",
    "enabled": true,
    "severity": "medium",
    "conditions": {
        "threshold": {
            "event_type": "data_access",
            "count": 1
        },
        "pattern_match": {
            "metadata.data_type": "(?i)(phi|medical|health)"
        },
        "time_constraint": {
            "hours": [0, 1, 2, 3, 4, 5, 6, 19, 20, 21, 22, 23]
        }
    },
    "timeframe": 3600,
    "risk_score": 60.0
}
```

## Advanced Correlation Rules

#### APT-Style Attack Chain
```json
{
    "name": "Advanced Persistent Threat Indicators",
    "description": "Multiple stages of APT attack detected",
    "enabled": true,
    "severity": "critical",
    "conditions": {
        "sequence": [
            {"event_type": "phishing_email", "count": 1},
            {"event_type": "malware_execution", "count": 1},
            {"event_type": "privilege_escalation", "count": 1},
            {"event_type": "lateral_movement", "count": 1},
            {"event_type": "data_exfiltration", "count": 1}
        ],
        "group_by": ["source_ip"],
        "ordered": true
    },
    "timeframe": 86400,  // 24 hours
    "risk_score": 100.0
}
```

## Testing Rules

Use the sample log generator to test these rules:

```bash
# Generate events that should trigger rules
python sample_log_generator.py --mode brute-force  # Triggers "SSH Brute Force Attack"
python sample_log_generator.py --mode port-scan    # Triggers "Network Port Scan"
python sample_log_generator.py --mode web-attack   # Triggers "SQL Injection Detected"
```

## Rule Tuning Guidelines

1. **Start Conservative**: Begin with higher thresholds to minimize false positives
2. **Monitor for a Week**: Observe normal patterns in your environment
3. **Adjust Gradually**: Lower thresholds incrementally
4. **Whitelist Known Good**: Exclude trusted IPs/users from certain rules
5. **Seasonal Adjustments**: Account for business cycles (month-end, holidays)
6. **Regular Review**: Quarterly assessment of rule effectiveness

## False Positive Reduction

### Common Causes
- **Automated Systems**: Backup jobs, monitoring tools, scheduled tasks
- **Business Patterns**: Month-end reporting, peak shopping seasons
- **Development**: QA testing, penetration testing, security scanning

### Solutions
- **Time-Based Exceptions**: Disable rules during maintenance windows
- **IP Whitelisting**: Exclude known scanner/monitor IPs
- **User Whitelisting**: Exclude service accounts from certain rules
- **Adaptive Thresholds**: Use baseline anomaly detection instead of fixed counts

---

For more information on implementing these rules, see the main README.md.
