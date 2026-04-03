import os
import json
import time
from mailer import send_email_alert
from notifier import send_slack_alert, send_sms_alert, send_onesignal_push

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
HISTORY_FILE = os.path.join(BASE_DIR, "alert_history.json")

ip_history = {}

def get_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    return {
        "email_recipients": "",
        "slack_webhook": "",
        "sms_recipient": "",
        "onesignal_app_id": "",
        "onesignal_api_key": "",
        "onesignal_player_id": "",
        "threshold_count": 5,
        "threshold_minutes": 5
    }

def save_config(config_data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=2)

def append_history(channel, target, timestamp, event_desc):
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            try:
                history = json.load(f)
            except:
                pass
            
    history.insert(0, {
        "channel": channel,
        "target": target,
        "timestamp": timestamp,
        "event": event_desc
    })
    
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def read_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            try:
                return json.load(f)
            except:
                return []
    return []

def track_and_alert(ip, username, timestamp, risk_level, reason):
    """
    Main orchestration logic for Task 3 requirements.
    Evaluates thresholds and fires notifications if constraints are breached.
    """
    config = get_config()
    now = time.time()
    
    count = int(config.get("threshold_count", 5))
    minutes = int(config.get("threshold_minutes", 5))
    
    if ip not in ip_history:
        ip_history[ip] = []
    
    # Prune old queries outside the time bracket
    ip_history[ip] = [t for t in ip_history[ip] if now - t < (minutes * 60)]
    ip_history[ip].append(now)
    
    trigger_alerts = False
    
    # Always trigger on High Risk based on PRD
    if risk_level == "HIGH RISK":
        trigger_alerts = True
    elif len(ip_history[ip]) >= count:
        trigger_alerts = True
        risk_level = "THRESHOLD TRIGGERED"
        reason = f"Exceeded Limit ({count} suspicious attempts inside {minutes} mins)"
        
    if trigger_alerts:
        event_desc = f"[{risk_level}] IP: {ip} | User: {username} | {reason}"
        
        # Slack Webhook Notification
        if config.get("slack_webhook"):
            ok = send_slack_alert(config["slack_webhook"], ip, username, timestamp, risk_level, reason)
            if ok: append_history("Slack", "Channel", timestamp, event_desc)
            
        # Email Notification (SendGrid/SMTP Fallback)
        emails = [e.strip() for e in config.get("email_recipients", "").split(",") if e.strip()]
        for email in emails:
            ok = send_email_alert(email, ip, username, timestamp, risk_level, reason)
            if ok: append_history("Email", email, timestamp, event_desc)
            
        # Twilio optional SMS module
        if config.get("sms_recipient"):
            ok = send_sms_alert(config["sms_recipient"], ip, risk_level)
            if ok: append_history("SMS", config["sms_recipient"], timestamp, event_desc)

        # OneSignal Mobile Push Notification
        os_app = config.get("onesignal_app_id") or os.getenv("ONESIGNAL_APP_ID", "")
        os_key = config.get("onesignal_api_key") or os.getenv("ONESIGNAL_API_KEY", "")
        os_pid = config.get("onesignal_player_id") or os.getenv("ONESIGNAL_PLAYER_ID", "")
        if os_app and os_key and os_pid:
            ok = send_onesignal_push(os_app, os_key, os_pid, ip, username, timestamp, risk_level, reason)
            if ok: append_history("Push (Mobile)", "OneSignal", timestamp, event_desc)
