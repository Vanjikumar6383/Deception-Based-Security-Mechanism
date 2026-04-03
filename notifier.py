import os
import json
import urllib.request
import urllib.parse
import base64

def send_slack_alert(webhook_url, ip, username, timestamp, risk_level, reason):
    """Sends a Slack notification using Block Kit styling"""
    if not webhook_url:
        return False
    
    color = "#ff1e38" if "HIGH RISK" in risk_level else "#ffb142"
    
    payload = {
        "text": f"🚨 *{risk_level} Deception Engine Triggered* 🚨",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Target IP", "value": ip, "short": True},
                    {"title": "Username Used", "value": username, "short": True},
                    {"title": "Timestamp", "value": timestamp, "short": True},
                    {"title": "Detection Reason", "value": reason, "short": False}
                ]
            }
        ]
    }
    
    try:
        req = urllib.request.Request(webhook_url, data=json.dumps(payload).encode('utf-8'),
                              headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req)
        return True
    except Exception as e:
        print(f"Error sending Slack alert: {e}")
        return False

def send_sms_alert(phone_to, ip, risk_level):
    """Optional Twilio SMS integration without heavily relying on their external lib"""
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    phone_from = os.getenv("TWILIO_FROM_NUMBER")
    
    if not phone_to or not sid or not token or not phone_from:
        return False
        
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    auth = base64.b64encode(f"{sid}:{token}".encode()).decode('utf-8')
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = urllib.parse.urlencode({
        "To": phone_to,
        "From": phone_from,
        "Body": f"🚨 {risk_level} Alert! Hostile IP detected: {ip}. View forensic dashboard immediately."
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        urllib.request.urlopen(req)
        return True
    except Exception as e:
        print(f"Error sending SMS: {e}")
        return False


def send_onesignal_push(app_id, api_key, player_id, ip, username, timestamp, risk_level, reason):
    """
    Sends a mobile push notification via OneSignal REST API.
    
    Requires:
      - app_id: Your OneSignal App ID
      - api_key: Your OneSignal REST API Key
      - player_id: The target device's OneSignal Player ID (or external_user_id)
    """
    if not app_id or not api_key or not player_id:
        return False

    url = "https://onesignal.com/api/v1/notifications"

    # Build payload for OneSignal Push
    payload = {
        "app_id": app_id,
        "include_player_ids": [player_id],
        "headings": {"en": f"🚨 {risk_level} — Honeypot Alert"},
        "contents": {"en": f"IP: {ip} | User: {username} | {reason}"},
        "data": {
            "ip": ip,
            "username": username,
            "timestamp": timestamp,
            "risk_level": risk_level,
            "reason": reason
        },
        "priority": 10,
        "android_accent_color": "FFFF1E38",
        "small_icon": "ic_stat_onesignal_default"
    }

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Basic {api_key}"
    }

    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read().decode('utf-8'))
        print(f"[OneSignal] Push sent. Recipients: {result.get('recipients', 0)}")
        return True
    except Exception as e:
        print(f"Error sending OneSignal push: {e}")
        return False
