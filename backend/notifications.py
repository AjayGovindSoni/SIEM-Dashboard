"""
Alert notification system for SIEM Dashboard
Supports Email, Slack, and generic webhooks

Configuration is loaded from environment variables (see .env.example).
"""

import os
import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from models import Alert, Incident
import logging

logger = logging.getLogger(__name__)


class AlertNotificationConfig:
    """Configuration for alert notifications — values read from environment variables."""

    # Email configuration
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    FROM_EMAIL: str = os.getenv("FROM_EMAIL", os.getenv("SMTP_USERNAME", ""))
    DEFAULT_TO_EMAIL: str = os.getenv("DEFAULT_TO_EMAIL", "security-team@example.com")

    # Slack configuration
    SLACK_WEBHOOK_URL: str = os.getenv(
        "SLACK_WEBHOOK_URL",
        "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    )

    # Webhook configuration
    CUSTOM_WEBHOOK_URL: str = os.getenv(
        "CUSTOM_WEBHOOK_URL",
        "https://your-webhook-endpoint.com/alerts",
    )


class EmailNotifier:
    """Send email notifications"""

    def __init__(self, config: AlertNotificationConfig):
        self.config = config

    def send(self, incident: Incident, recipients: List[str] = None) -> bool:
        """Send email alert for incident"""
        if not self.config.SMTP_USERNAME or not self.config.SMTP_PASSWORD:
            logger.warning(
                "Email not configured — set SMTP_USERNAME and SMTP_PASSWORD in your .env file."
            )
            return False

        try:
            if not recipients:
                recipients = [self.config.DEFAULT_TO_EMAIL]

            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SIEM Alert] {incident.severity.upper()}: {incident.title}"
            msg["From"] = self.config.FROM_EMAIL
            msg["To"] = ", ".join(recipients)

            # Create HTML and text versions
            text_content = self._create_text_email(incident)
            html_content = self._create_html_email(incident)

            msg.attach(MIMEText(text_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            # Send email
            with smtplib.SMTP(self.config.SMTP_SERVER, self.config.SMTP_PORT) as server:
                server.starttls()
                server.login(self.config.SMTP_USERNAME, self.config.SMTP_PASSWORD)
                server.send_message(msg)

            logger.info(f"Email alert sent for incident {incident.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def _create_text_email(self, incident: Incident) -> str:
        """Create plain text email content"""
        return f"""
SECURITY INCIDENT ALERT

Incident ID: {incident.id}
Title: {incident.title}
Severity: {incident.severity.upper()}
Status: {incident.status}
Risk Score: {incident.risk_score}

Description:
{incident.description}

Details:
- Source IP: {incident.source_ip or 'N/A'}
- Username: {incident.username or 'N/A'}
- Hostname: {incident.hostname or 'N/A'}
- First Seen: {incident.first_seen}
- Last Seen: {incident.last_seen}
- Event Count: {incident.event_count}

Please investigate this incident immediately.

---
SIEM Dashboard Alert System
        """

    def _create_html_email(self, incident: Incident) -> str:
        """Create HTML email content"""
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#f59e0b",
            "low": "#3b82f6",
            "info": "#6b7280",
        }

        color = severity_colors.get(incident.severity, "#6b7280")

        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: {color}; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .detail {{ margin: 10px 0; }}
                .label {{ font-weight: bold; }}
                .footer {{ margin-top: 30px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 SECURITY INCIDENT ALERT</h1>
                <h2>{incident.title}</h2>
            </div>
            <div class="content">
                <div class="detail">
                    <span class="label">Incident ID:</span> {incident.id}
                </div>
                <div class="detail">
                    <span class="label">Severity:</span>
                    <span style="color: {color}; font-weight: bold;">{incident.severity.upper()}</span>
                </div>
                <div class="detail">
                    <span class="label">Risk Score:</span> {incident.risk_score}
                </div>
                <div class="detail">
                    <span class="label">Status:</span> {incident.status}
                </div>

                <h3>Description</h3>
                <p>{incident.description}</p>

                <h3>Details</h3>
                <table>
                    <tr><td class="label">Source IP:</td><td>{incident.source_ip or 'N/A'}</td></tr>
                    <tr><td class="label">Username:</td><td>{incident.username or 'N/A'}</td></tr>
                    <tr><td class="label">Hostname:</td><td>{incident.hostname or 'N/A'}</td></tr>
                    <tr><td class="label">First Seen:</td><td>{incident.first_seen}</td></tr>
                    <tr><td class="label">Last Seen:</td><td>{incident.last_seen}</td></tr>
                    <tr><td class="label">Event Count:</td><td>{incident.event_count}</td></tr>
                </table>
            </div>
            <div class="footer">
                SIEM Dashboard Alert System - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </body>
        </html>
        """


class SlackNotifier:
    """Send Slack notifications"""

    def __init__(self, config: AlertNotificationConfig):
        self.config = config

    def send(self, incident: Incident) -> bool:
        """Send Slack alert for incident"""
        if "YOUR/WEBHOOK" in self.config.SLACK_WEBHOOK_URL:
            logger.warning(
                "Slack not configured — set SLACK_WEBHOOK_URL in your .env file."
            )
            return False

        try:
            message = self._create_slack_message(incident)

            response = requests.post(
                self.config.SLACK_WEBHOOK_URL,
                json=message,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            if response.status_code == 200:
                logger.info(f"Slack alert sent for incident {incident.id}")
                return True
            else:
                logger.error(f"Slack alert failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

    def _create_slack_message(self, incident: Incident) -> Dict[str, Any]:
        """Create Slack message payload"""
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#f59e0b",
            "low": "#3b82f6",
            "info": "#6b7280",
        }

        severity_emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }

        emoji = severity_emojis.get(incident.severity, "⚪")
        color = severity_colors.get(incident.severity, "#6b7280")

        return {
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} Security Incident Alert",
                    "title_link": f"http://localhost:{os.getenv('API_PORT', '8001')}/incidents/{incident.id}",
                    "text": incident.title,
                    "fields": [
                        {"title": "Severity", "value": incident.severity.upper(), "short": True},
                        {"title": "Risk Score", "value": str(incident.risk_score), "short": True},
                        {"title": "Source IP", "value": incident.source_ip or "N/A", "short": True},
                        {"title": "Event Count", "value": str(incident.event_count), "short": True},
                        {"title": "Description", "value": incident.description, "short": False},
                    ],
                    "footer": "SIEM Dashboard",
                    "ts": (
                        int(incident.created_at.timestamp())
                        if incident.created_at
                        else int(datetime.now().timestamp())
                    ),
                }
            ]
        }


class WebhookNotifier:
    """Send generic webhook notifications"""

    def __init__(self, config: AlertNotificationConfig):
        self.config = config

    def send(self, incident: Incident, webhook_url: str = None) -> bool:
        """Send webhook alert for incident"""
        url = webhook_url or self.config.CUSTOM_WEBHOOK_URL

        if "your-webhook-endpoint" in url:
            logger.warning(
                "Custom webhook not configured — set CUSTOM_WEBHOOK_URL in your .env file."
            )
            return False

        try:
            payload = self._create_webhook_payload(incident)

            response = requests.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            if response.status_code in [200, 201, 202]:
                logger.info(f"Webhook alert sent for incident {incident.id}")
                return True
            else:
                logger.error(f"Webhook alert failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

    def _create_webhook_payload(self, incident: Incident) -> Dict[str, Any]:
        """Create webhook payload"""
        return {
            "event_type": "security_incident",
            "timestamp": datetime.now().isoformat(),
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "risk_score": incident.risk_score,
                "source_ip": incident.source_ip,
                "username": incident.username,
                "hostname": incident.hostname,
                "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
                "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
                "event_count": incident.event_count,
            },
        }


class AlertNotificationManager:
    """Manage all alert notifications"""

    def __init__(self, config: AlertNotificationConfig = None):
        self.config = config or AlertNotificationConfig()
        self.email_notifier = EmailNotifier(self.config)
        self.slack_notifier = SlackNotifier(self.config)
        self.webhook_notifier = WebhookNotifier(self.config)

    def send_alert(
        self,
        incident: Incident,
        db: Session,
        methods: List[str] = None,
        recipients: List[str] = None,
    ):
        """Send alert notifications for incident"""
        if methods is None:
            # Determine methods based on severity
            if incident.severity == "critical":
                methods = ["email", "slack", "webhook"]
            elif incident.severity == "high":
                methods = ["email", "slack"]
            else:
                methods = ["email"]

        results = {}

        for method in methods:
            alert = Alert(
                incident_id=incident.id,
                alert_type=method,
                status="pending",
            )

            try:
                success = False

                if method == "email":
                    alert.recipient = (
                        ", ".join(recipients) if recipients else self.config.DEFAULT_TO_EMAIL
                    )
                    success = self.email_notifier.send(incident, recipients)

                elif method == "slack":
                    alert.recipient = "Slack Channel"
                    success = self.slack_notifier.send(incident)

                elif method == "webhook":
                    alert.recipient = "Webhook Endpoint"
                    success = self.webhook_notifier.send(incident)

                if success:
                    alert.status = "sent"
                    alert.sent_at = datetime.utcnow()
                else:
                    alert.status = "failed"
                    alert.error_message = "Notification failed to send"

                results[method] = success

            except Exception as e:
                alert.status = "failed"
                alert.error_message = str(e)
                results[method] = False
                logger.error(f"Alert notification failed for {method}: {e}")

            finally:
                db.add(alert)

        db.commit()
        return results


# Global notification manager (config auto-loads from environment)
notification_manager = AlertNotificationManager()
