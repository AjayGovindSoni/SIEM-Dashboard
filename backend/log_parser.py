import re
import json
from datetime import datetime
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class LogParser(ABC):
    """Base class for log parsers"""
    
    @abstractmethod
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line and return normalized event"""
        pass
    
    @staticmethod
    def determine_severity(event_type: str, message: str) -> str:
        """Determine severity based on event type and message content"""
        message_lower = message.lower()
        
        # Critical indicators
        if any(word in message_lower for word in ['exploit', 'breach', 'compromise', 'ransomware', 'rootkit']):
            return 'critical'
        
        # High severity
        if any(word in event_type.lower() for word in ['malware', 'intrusion', 'unauthorized']):
            return 'high'
        if any(word in message_lower for word in ['attack', 'malicious', 'threat', 'suspicious']):
            return 'high'
        
        # Medium severity
        if any(word in event_type.lower() for word in ['failed', 'denied', 'blocked', 'alert']):
            return 'medium'
        
        # Low severity
        if any(word in event_type.lower() for word in ['warning', 'notice']):
            return 'low'
        
        # Default to info
        return 'info'


class SyslogParser(LogParser):
    """Parser for RFC3164/RFC5424 syslog messages"""
    
    # RFC3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    RFC3164_PATTERN = re.compile(
        r'<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.*)'
    )
    
    # RFC5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    RFC5424_PATTERN = re.compile(
        r'<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)'
    )
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse syslog message"""
        # Try RFC5424 first
        match = self.RFC5424_PATTERN.match(log_line)
        if match:
            return self._parse_rfc5424(match, log_line)
        
        # Try RFC3164
        match = self.RFC3164_PATTERN.match(log_line)
        if match:
            return self._parse_rfc3164(match, log_line)
        
        return None
    
    def _parse_rfc3164(self, match, raw_log: str) -> Dict[str, Any]:
        """Parse RFC3164 format"""
        priority, timestamp_str, hostname, tag, message = match.groups()
        
        # Parse timestamp (e.g., "Jan 15 10:30:45")
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except:
            timestamp = datetime.now()
        
        # Determine event type from tag
        event_type = self._classify_event(tag, message)
        severity = self.determine_severity(event_type, message)
        
        return {
            'timestamp': timestamp,
            'hostname': hostname,
            'event_type': event_type,
            'severity': severity,
            'category': self._categorize_event(tag, message),
            'message': message,
            'raw_log': raw_log,
            'event_metadata': {
                'priority': int(priority),
                'tag': tag,
                'format': 'RFC3164'
            }
        }
    
    def _parse_rfc5424(self, match, raw_log: str) -> Dict[str, Any]:
        """Parse RFC5424 format"""
        groups = match.groups()
        priority, version, timestamp_str, hostname, app_name, proc_id, msg_id, structured_data, message = groups
        
        # Parse ISO 8601 timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            timestamp = datetime.now()
        
        event_type = self._classify_event(app_name, message)
        severity = self.determine_severity(event_type, message)
        
        return {
            'timestamp': timestamp,
            'hostname': hostname,
            'event_type': event_type,
            'severity': severity,
            'category': self._categorize_event(app_name, message),
            'message': message,
            'raw_log': raw_log,
            'event_metadata': {
                'priority': int(priority),
                'version': int(version),
                'app_name': app_name,
                'proc_id': proc_id,
                'msg_id': msg_id,
                'structured_data': structured_data,
                'format': 'RFC5424'
            }
        }
    
    def _classify_event(self, tag: str, message: str) -> str:
        """Classify event type based on tag and message"""
        tag_lower = tag.lower()
        msg_lower = message.lower()
        
        # Authentication events
        if 'ssh' in tag_lower or 'login' in tag_lower or 'auth' in tag_lower:
            if 'failed' in msg_lower or 'invalid' in msg_lower:
                return 'failed_login'
            elif 'accepted' in msg_lower or 'success' in msg_lower:
                return 'successful_login'
            return 'authentication'
        
        # Network events
        if 'firewall' in tag_lower or 'iptables' in tag_lower:
            if 'block' in msg_lower or 'drop' in msg_lower or 'deny' in msg_lower:
                return 'network_blocked'
            return 'network_traffic'
        
        # Security events
        if 'ids' in tag_lower or 'snort' in tag_lower or 'suricata' in tag_lower:
            return 'intrusion_detection'
        
        if 'malware' in msg_lower or 'virus' in msg_lower:
            return 'malware_detection'
        
        return 'system_event'
    
    def _categorize_event(self, tag: str, message: str) -> str:
        """Categorize event into broad categories"""
        tag_lower = tag.lower()
        msg_lower = message.lower()
        
        if any(word in tag_lower for word in ['auth', 'login', 'ssh', 'pam']):
            return 'authentication'
        
        if any(word in tag_lower for word in ['firewall', 'iptables', 'network']):
            return 'network'
        
        if any(word in msg_lower for word in ['malware', 'virus', 'trojan']):
            return 'malware'
        
        if any(word in tag_lower for word in ['ids', 'ips', 'snort', 'suricata']):
            return 'intrusion_detection'
        
        return 'system'


class ApacheLogParser(LogParser):
    """Parser for Apache access/error logs"""
    
    # Combined log format
    COMBINED_PATTERN = re.compile(
        r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
    )
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse Apache log"""
        match = self.COMBINED_PATTERN.match(log_line)
        if not match:
            return None
        
        ip, ident, user, timestamp_str, request, status, size, referer, user_agent = match.groups()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except:
            timestamp = datetime.now()
        
        # Determine if suspicious
        status_code = int(status)
        event_type = 'http_request'
        severity = 'info'
        
        if status_code >= 400:
            event_type = 'http_error'
            severity = 'medium' if status_code < 500 else 'high'
        
        # Detect common attack patterns
        if any(pattern in request.lower() for pattern in ['script', 'union', 'select', '../', 'exec']):
            event_type = 'http_attack_attempt'
            severity = 'high'
        
        return {
            'timestamp': timestamp,
            'source_ip': ip,
            'username': user if user != '-' else None,
            'event_type': event_type,
            'severity': severity,
            'category': 'web',
            'message': f"{request} -> {status}",
            'raw_log': log_line,
            'event_metadata': {
                'request': request,
                'status_code': status_code,
                'size': size,
                'referer': referer,
                'user_agent': user_agent
            }
        }


class JSONLogParser(LogParser):
    """Parser for JSON-formatted logs"""
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON log"""
        try:
            data = json.loads(log_line)
        except json.JSONDecodeError:
            return None
        
        # Extract common fields
        timestamp_str = data.get('timestamp') or data.get('time') or data.get('@timestamp')
        try:
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.now()
        except:
            timestamp = datetime.now()
        
        event_type = data.get('event_type') or data.get('type') or 'json_event'
        message = data.get('message') or data.get('msg') or str(data)
        
        return {
            'timestamp': timestamp,
            'source_ip': data.get('source_ip') or data.get('src_ip'),
            'destination_ip': data.get('dest_ip') or data.get('dst_ip'),
            'username': data.get('user') or data.get('username'),
            'hostname': data.get('host') or data.get('hostname'),
            'event_type': event_type,
            'severity': data.get('severity') or self.determine_severity(event_type, message),
            'category': data.get('category') or 'custom',
            'message': message,
            'raw_log': log_line,
            'event_metadata': data
        }


class LogParserFactory:
    """Factory for creating appropriate parser based on log format"""
    
    @staticmethod
    def get_parser(log_format: str = 'auto') -> LogParser:
        """Get parser for specified format"""
        if log_format == 'syslog':
            return SyslogParser()
        elif log_format == 'apache':
            return ApacheLogParser()
        elif log_format == 'json':
            return JSONLogParser()
        elif log_format == 'auto':
            # Return auto-detecting parser
            return AutoDetectParser()
        else:
            raise ValueError(f"Unknown log format: {log_format}")


class AutoDetectParser(LogParser):
    """Auto-detect log format and parse accordingly"""
    
    def __init__(self):
        self.syslog_parser = SyslogParser()
        self.apache_parser = ApacheLogParser()
        self.json_parser = JSONLogParser()
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Try each parser until one succeeds"""
        # Try JSON first (most structured)
        if log_line.strip().startswith('{'):
            result = self.json_parser.parse(log_line)
            if result:
                return result
        
        # Try syslog (common format)
        if log_line.strip().startswith('<'):
            result = self.syslog_parser.parse(log_line)
            if result:
                return result
        
        # Try Apache
        result = self.apache_parser.parse(log_line)
        if result:
            return result
        
        # If all fail, create a generic event
        return {
            'timestamp': datetime.now(),
            'event_type': 'unparsed_log',
            'severity': 'info',
            'category': 'unknown',
            'message': log_line[:500],  # Truncate long lines
            'raw_log': log_line,
            'event_metadata': {}
        }
