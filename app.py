"""
Deception-Based Security Mechanism — Flask Application
Follows PRD Guidelines:
- Fake login system -> Honeypot dummy website
- SQL Injection and Bypass detection inside dummy site
- Dashboard popup alerts on attacks
- Threat Classification (NORMAL, SUSPICIOUS, HIGH RISK)
- Threat Intel Dashboard with Alert History Array
- Rate Limiting and tracking persisted thresholds
"""

import os
import json
import hashlib
import time
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from dotenv import load_dotenv

# Load env variables required for Flask-Mail / Twilio / Slack hooks
load_dotenv()

# We import the new task3 modular orchestration engine
from alert_manager import track_and_alert, get_config, save_config, read_history

app = Flask(__name__)
app.secret_key = "deception-security-key-2026"

# ---------------------------------------------------------------------------
# File Paths & State
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs.json")
ALERTS_FILE = os.path.join(BASE_DIR, "alerts.json")
DB_FILE = os.path.join(BASE_DIR, "dummy.db")

# In-memory tracking for rate-limiting (Repeated login attempts)
ip_attempts = {}
# (username, ip) -> set of passwords tried
user_password_attempts = {}

def get_time():
    """Returns current Indian Standard Time (IST) string formatting"""
    from datetime import timezone, timedelta
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

# ---------------------------------------------------------------------------
# Dummy Database Initialization (Legitimate System)
# ---------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, item TEXT, order_number TEXT, amount TEXT, status TEXT)''')
    
    # Force reset testing credentials
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin')")
    
    # Check dummy orders
    c.execute("SELECT COUNT(*) FROM orders")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO orders (item, order_number, amount, status) VALUES ('NovaBook Pro - 16inch', 'ORD-99824X', '$2,499.00', 'Processing')")
        c.execute("INSERT INTO orders (item, order_number, amount, status) VALUES ('Quantum X-900 GPU', 'ORD-77431A', '$1,299.00', 'Shipped Securely')")
        
    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------------------------
# Persistence Helpers
# ---------------------------------------------------------------------------

def _read_json(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def append_log(entry):
    logs = _read_json(LOG_FILE)
    prev_hash = logs[-1].get("hash", "0" * 64) if logs else "0" * 64
    entry["prev_hash"] = prev_hash
    payload = json.dumps(entry, sort_keys=True).encode()
    entry["hash"] = hashlib.sha256(payload).hexdigest()
    logs.append(entry)
    _write_json(LOG_FILE, logs)

def append_alert(alert):
    alerts = _read_json(ALERTS_FILE)
    alerts.insert(0, alert)
    _write_json(ALERTS_FILE, alerts)

# ---------------------------------------------------------------------------
# Threat Analysis Engine
# ---------------------------------------------------------------------------

HIGH_RISK_USERNAMES = {"admin", "root", "administrator", "superuser", "sa", "sysadmin"}
SQLI_PAYLOADS = ["'", '"', "or 1=1", "union select", ";--", "drop table", "1=1", "/*", "xp_cmdshell"]
XSS_PAYLOADS = ["<script>", "onload=", "onerror=", "javascript:"]

def check_rate_limit(client_ip):
    """Monitor repeated login attempts (Max 3 per minute)"""
    now = time.time()
    if client_ip not in ip_attempts:
        ip_attempts[client_ip] = []
    
    ip_attempts[client_ip] = [t for t in ip_attempts[client_ip] if now - t < 60]
    ip_attempts[client_ip].append(now)
    
    return len(ip_attempts[client_ip])

# ---------------------------------------------------------------------------
# Routes — Dummy Legitimate App & Deception Layer
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("logs_dashboard"))

@app.route("/novamart", methods=["GET"])
def novamart():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    client_ip = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")

    if request.method == "GET":
        append_log({
            "timestamp": get_time(),
            "ip_address": client_ip,
            "username": "N/A",
            "password": "N/A",
            "user_agent": user_agent,
            "risk_level": "NORMAL",
            "reason": "Regular page load (GET access)"
        })
        return render_template("login.html")

    # Handle POST (Login Attempt)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    
    attempt_count = check_rate_limit(client_ip)
    
    u_lower = username.lower()
    p_lower = password.lower()
    
    # 1. First Pass: Detect strict bypass payloads
    if any(payload in u_lower for payload in SQLI_PAYLOADS) or any(payload in p_lower for payload in SQLI_PAYLOADS):
        risk_level = "HIGH RISK"
        reason = "SQL Injection / Site Bypass attempt detected on login"
    elif attempt_count > 3:
        risk_level = "HIGH RISK"
        reason = "Repeated login attempts (Brute Force Detected)"
    else:
        # 2. Second Pass: Check Database for Legitimate Login 
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        db_user = c.fetchone()
        conn.close()

        if db_user:
            # Verified Legitimate Identity! Bypass honeypot completely.
            session['logged_in'] = True
            session['username'] = username
            
            append_log({
                "timestamp": get_time(),
                "ip_address": client_ip,
                "username": username,
                "password": "[REDACTED]", 
                "user_agent": user_agent,
                "risk_level": "NORMAL",
                "reason": "Legitimate Admin Authentication Success. Redirected safely to Storefront."
            })
            return redirect(url_for("novamart"))

        elif u_lower in HIGH_RISK_USERNAMES:
            # Failed to verify password + High Risk Target Name 
            risk_level = "HIGH RISK"
            reason = f"High-risk root username '{username}' targeted (Failed Auth)"
        else:
            # Failed to verify password + Normal Name -> Accept into Honeypot Fake Panel
            risk_level = "NORMAL"
            reason = "Accepted naive credentials into Honeypot Dummy Site"

    if risk_level == "NORMAL":
        # Check if this user is becoming suspicious (multiple unique password attempts)
        key = (username, client_ip)
        if key not in user_password_attempts:
            user_password_attempts[key] = set()
        user_password_attempts[key].add(password)
        
        # If they've tried more than one unique password, elevate to SUSPICIOUS
        final_risk = "SUSPICIOUS" if len(user_password_attempts[key]) > 1 else "NORMAL"
        final_reason = reason if len(user_password_attempts[key]) <= 1 else f"Multiple passwords attempted for user '{username}'"

        # Honeypot TRAP: Accept normal-looking (but wrong) usernames to lure attackers.
        session['logged_in'] = True
        session['username'] = username
        
        append_log({
            "timestamp": get_time(),
            "ip_address": client_ip,
            "username": username,
            "password": "HIDDEN", 
            "user_agent": user_agent,
            "risk_level": final_risk,
            "reason": final_reason
        })
        return redirect(url_for("home"))
    else:
        # Malicious attempt triggers alarm immediately
        event = {
            "timestamp": get_time(),
            "ip_address": client_ip,
            "username": username,
            "password": password, # Capture malicious payloads
            "user_agent": user_agent,
            "risk_level": risk_level,
            "reason": reason,
        }
        append_log(event)

        if risk_level == "HIGH RISK":
            append_alert({
                "timestamp": get_time(),
                "type": "HIGH RISK LOGIN",
                "ip": client_ip,
                "username": username,
                "message": reason,
            })
            
        # Hook into Task 3 modular notification engine
        track_and_alert(client_ip, username, get_time(), risk_level, reason)

        flash("Authentication failed. Invalid credentials or secure connection terminated.", "danger")
        return redirect(url_for("login"))

@app.route("/home")
def home():
    if not session.get('logged_in'):
        return redirect(url_for("login"))
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT item, order_number, status, amount FROM orders")
    orders = c.fetchall()
    conn.close()
    
    return render_template("honeypot.html", username=session['username'], items=orders)

@app.route("/search")
def search():
    if not session.get('logged_in'):
        return redirect(url_for("login"))

    query = request.args.get("q", "").strip()
    client_ip = request.remote_addr or "unknown"
    q_lower = query.lower()

    # Detect attack inside the dummy website!
    if any(payload in q_lower for payload in SQLI_PAYLOADS) or any(payload in q_lower for payload in XSS_PAYLOADS):
        alert_msg = f"In-Site Attack vector used in search: {query}"
        event = {
            "timestamp": get_time(),
            "ip_address": client_ip,
            "username": session.get('username'),
            "password": "N/A",
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "risk_level": "HIGH RISK",
            "reason": alert_msg,
        }
        append_log(event)
        append_alert({
            "timestamp": get_time(),
            "type": "HONEYPOT IN-SITE ATTACK",
            "ip": client_ip,
            "username": session.get('username'),
            "message": alert_msg,
        })
        # Simulate a fake DB error to encourage the attacker
        return f"Warning: sqlite3.OperationalError: near '{query}': syntax error", 500

    # Legitimate search flow
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT item, order_number, status, amount FROM orders WHERE item LIKE ? OR order_number LIKE ?", ('%'+query+'%', '%'+query+'%'))
    orders = c.fetchall()
    conn.close()
    
    return render_template("honeypot.html", username=session['username'], items=orders, query=query)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Traps: Catching Security Scans & Sensitive Files
# ---------------------------------------------------------------------------

@app.route("/robots.txt")
@app.route("/.git/<path:subpath>")
@app.route("/.git")
@app.route("/wp-admin")
@app.route("/wp-admin/<path:subpath>")
@app.route("/wp-login.php")
@app.route("/config.php")
def scan_trap(subpath=""):
    """Catch common automated security vulnerability scans"""
    client_ip = request.remote_addr or "unknown"
    path = request.path

    event = {
        "timestamp": get_time(),
        "ip_address": client_ip,
        "username": "N/A",
        "password": "N/A",
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "risk_level": "HIGH RISK",
        "reason": f"Automated Security Scan / Recon detected: {path}",
    }
    append_log(event)
    append_alert({
        "timestamp": get_time(),
        "type": "RECON SCAN",
        "ip": client_ip,
        "username": "N/A",
        "message": f"Security scanner probing detected on path: {path}",
    })
    
    # Task 3 Notify Mod
    track_and_alert(client_ip, "N/A", get_time(), "HIGH RISK", f"Recon scan hit trap at {path}")
    
    return render_template("alert.html"), 403

@app.route("/admin-secret", methods=["GET", "POST"])
@app.route("/api/internal/config", methods=["GET", "POST"])
@app.route("/.env", methods=["GET", "POST"])
def hidden_trap():
    """Hidden endpoints representing sensitive internal files"""
    client_ip = request.remote_addr or "unknown"
    path = request.path

    event = {
        "timestamp": get_time(),
        "ip_address": client_ip,
        "username": "N/A",
        "password": "N/A",
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "risk_level": "HIGH RISK",
        "reason": f"Sensitive file access violation: {path}",
    }
    
    append_log(event)
    append_alert({
        "timestamp": get_time(),
        "type": "RESOURCE PROBE",
        "ip": client_ip,
        "username": "N/A",
        "message": f"Unauthorized access to sensitive configuration: {path}",
    })

    # Task 3 Notify Mod
    track_and_alert(client_ip, "N/A", get_time(), "HIGH RISK", f"Resource probe trap hit at {path}")

    return render_template("alert.html"), 403

@app.errorhandler(404)
def handle_404(e):
    """Catch all unknown paths as generic directory probes"""
    client_ip = request.remote_addr or "unknown"
    path = request.path
    
    event = {
        "timestamp": get_time(),
        "ip_address": client_ip,
        "username": "N/A",
        "password": "N/A",
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "risk_level": "SUSPICIOUS",
        "reason": f"Directory probe (404 Not Found) on: {path}",
    }
    append_log(event)
    
    # Task 3: Feed this into the Alert Manager to track for Threshold scanning (e.g., Dirbuster)
    track_and_alert(client_ip, "N/A", get_time(), "SUSPICIOUS", f"404 Directory Probe at {path}")
    
    return "NovaMart E-Commerce System: Route Not Found", 404

# ---------------------------------------------------------------------------
# Routes — Threat Intel Dashboard & Settings (High-end Admin panel)
# ---------------------------------------------------------------------------

@app.route("/logs")
def logs_dashboard():
    """Admin High-End Graphics Dashboard showing alerts, intel, and history"""
    logs = _read_json(LOG_FILE)
    alerts = _read_json(ALERTS_FILE)
    history = read_history()
    logs.reverse()  # newest first
    return render_template("admin.html", logs=logs, alerts=alerts, history=history)

@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    """Task 3 Configurable Alert Settings page"""
    if request.method == "POST":
        new_config = {
            "email_recipients": request.form.get("email_recipients", ""),
            "slack_webhook": request.form.get("slack_webhook", ""),
            "sms_recipient": request.form.get("sms_recipient", ""),
            "onesignal_app_id": request.form.get("onesignal_app_id", ""),
            "onesignal_api_key": request.form.get("onesignal_api_key", ""),
            "onesignal_player_id": request.form.get("onesignal_player_id", ""),
            "threshold_count": int(request.form.get("threshold_count", 5)),
            "threshold_minutes": int(request.form.get("threshold_minutes", 5))
        }
        save_config(new_config)
        flash("Telemetry settings saved securely to system core.")
        return redirect(url_for("admin_settings"))
        
    current_config = get_config()
    return render_template("settings.html", config=current_config)

# Legacy redirect removed. /admin is now a TRAP.
@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin.php", methods=["GET", "POST"])
def admin_trap():
    """TRAP: Anyone attempting to find the Admin Panel gets caught."""
    client_ip = request.remote_addr or "unknown"
    path = request.path

    event = {
        "timestamp": get_time(),
        "ip_address": client_ip,
        "username": "N/A",
        "password": "N/A",
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "risk_level": "HIGH RISK",
        "reason": f"Targeted Admin Console access violation: {path}",
    }
    
    append_log(event)
    append_alert({
        "timestamp": get_time(),
        "type": "HIGH RISK BYPASS",
        "ip": client_ip,
        "username": "N/A",
        "message": f"Unauthorized attempt to access Admin Control Panel at {path}.",
    })

    # Task 3 Notify Mod
    track_and_alert(client_ip, "N/A", get_time(), "HIGH RISK", f"Admin panel trap triggered")

    return render_template("alert.html"), 401

@app.route("/api/latest_alert")
def latest_alert():
    """API endpoint for Dashboard to poll real-time popups"""
    alerts = _read_json(ALERTS_FILE)
    if alerts:
        return jsonify(alerts[0])
    return jsonify({})

if __name__ == "__main__":
    init_db()
    if not os.path.exists(LOG_FILE): _write_json(LOG_FILE, [])
    if not os.path.exists(ALERTS_FILE): _write_json(ALERTS_FILE, [])
    
    app.run(debug=True, port=5000)
