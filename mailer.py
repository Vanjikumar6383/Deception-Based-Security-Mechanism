import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(recipient, ip, username, timestamp, risk_level, reason):
    """Sends an email alert using Flask-Mail equivalent logic via SMTP"""
    server = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    port = int(os.getenv("MAIL_PORT", "587"))
    sender = os.getenv("MAIL_USERNAME")
    password = os.getenv("MAIL_PASSWORD")

    if not sender or not password or not recipient:
        return False
        
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = f"🚨 {risk_level} Security Alert: Deception Framework"
    
    body = f"""
    Deception Alert Engine triggered.
    ---------------------------------
    Risk Level: {risk_level}
    Timestamp: {timestamp}
    Target IP: {ip}
    Username Attempted: {username}
    Trigger Reason: {reason}
    
    View Full Forensics: http://localhost:5000/logs
    """
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        s = smtplib.SMTP(server, port)
        s.starttls()
        s.login(sender, password)
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
