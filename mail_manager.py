import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
import config

class MailManager:
    def __init__(self):
        self.server = config.SMTP_SERVER
        self.port = config.SMTP_PORT
        self.user = config.SMTP_USER
        self.password = config.SMTP_PASS

    def send_report(self, pdf_path, recipient):
        """Sends the generated PDF report via Gmail SMTP."""
        if not os.path.exists(pdf_path):
            print(f"Error: PDF report not found at {pdf_path}")
            return False

        message = MIMEMultipart()
        message["From"] = self.user
        message["To"] = recipient
        message["Subject"] = f"AI Firewall Monitoring Report - {os.path.basename(pdf_path)}"

        body = f"Attached is your daily AI-Powered Firewall Monitoring Report for {os.path.basename(pdf_path)}.\n\n"
        body += "This report includes forensic traffic analysis, login monitoring, policy change detection, and internet bandwidth stats."
        message.attach(MIMEText(body, "plain"))

        # Attach PDF
        try:
            with open(pdf_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={os.path.basename(pdf_path)}",
            )
            message.attach(part)

            # Send Email
            with smtplib.SMTP(self.server, self.port) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.send_message(message)
            print(f"Successfully sent report to {recipient}")
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    def send_alert(self, alert_text):
        """Sends a high-priority security alert email."""
        from datetime import datetime # Ensure datetime is available
        message = MIMEMultipart()
        message["From"] = self.user
        message["To"] = config.RECIPIENT_MAIL
        message["Subject"] = f"⚠️ FIREWALL SECURITY ALERT - {datetime.now().strftime('%H:%M:%S')}"

        body = f"CRITICAL SECURITY EVENT DETECTED:\n\n{alert_text}\n\n"
        body += "Please check the FortiGate dashboard or local logs for immediate forensic details."
        message.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self.server, self.port) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.send_message(message)
            print(f"[ALERT] Security alert sent to {config.RECIPIENT_MAIL}")
            return True
        except Exception as e:
            print(f"Failed to send alert email: {e}")
            return False

    def send_login_alert(self, event):
        """Sends a near real-time notification for system login activities."""
        from datetime import datetime
        message = MIMEMultipart()
        message["From"] = self.user
        message["To"] = config.RECIPIENT_MAIL
        
        status = event.get('status', 'N/A').upper()
        action = event.get('action', 'N/A').upper()
        subject_prefix = "⚠️ AUTH ALERT" if "FAILED" in status else "ℹ️ LOGIN INFO"
        message["Subject"] = f"{subject_prefix}: {action} {status} - {event.get('user', 'ADMIN')}"

        body = f"SYSTEM AUTHENTICATION EVENT DETECTED:\n\n"
        body += f"  Admin User: {event.get('user', 'N/A')}\n"
        body += f"  Action    : {event.get('logdesc', 'N/A')}\n"
        body += f"  Source IP : {event.get('ui', event.get('srcip', 'N/A'))}\n"
        body += f"  Status    : {event.get('status', 'N/A')}\n"
        body += f"  Timestamp : {event.get('date')} {event.get('time')}\n\n"
        body += f"Details: {event.get('msg', 'N/A')}"
        
        message.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self.server, self.port) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.send_message(message)
            print(f"[AUTH ALERT] Login notification sent for {event.get('user')}")
            return True
        except Exception as e:
            print(f"Failed to send login alert: {e}")
            return False
