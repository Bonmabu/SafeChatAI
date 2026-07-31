from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from db import (
    calculate_risk_score,
    update_threat_intelligence,
    get_threat_intelligence,
    create_alert,
    create_audit_log,
    create_incident
)
from db import (
    get_category_distribution,
    get_executive_kpis
)
from db import (
    get_incidents,
    get_open_incidents,
    get_alerts,
    get_audit_logs,
    get_total_scans,
    get_total_alerts,
    get_total_incidents,
    get_open_incident_count,
    update_threat_intelligence,
    get_threat_intelligence
)
from db import update_threat_trends
from db import update_incident_status

import sqlite3
import threading
import asyncio
import datetime
import json
import smtplib
import csv
from fastapi import WebSocket
from typing import List

from email.mime.text import MIMEText
from collections import Counter

# =========================
# APP INIT
# =========================

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DB = "scams.db"
lock = threading.Lock()

API_KEY = "safechat-secret-123"
ALERT_EMAIL = "your_email@gmail.com"
ALERT_PASSWORD = "your_app_password"

SESSIONS = {}
ALERT_LOG = []

# =========================
# DB
# =========================

def get_conn():
    conn = sqlite3.connect(BASE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        category TEXT,
        risk_score INTEGER,
        status TEXT,
        user TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()


init_db()

# =========================
# ENGINE (placeholder hook)
# =========================

def analyze_text(text: str):

    text = text.lower()

    phishing_words = [
        "password",
        "verify",
        "account",
        "login",
        "bank",
        "click here"
    ]

    fraud_words = [
        "investment",
        "crypto",
        "double your money",
        "profit"
    ]

    scam_words = [
        "winner",
        "lottery",
        "claim now",
        "prize"
    ]

    phishing_hits = sum(
        1 for word in phishing_words
        if word in text
    )

    fraud_hits = sum(
        1 for word in fraud_words
        if word in text
    )

    scam_hits = sum(
        1 for word in scam_words
        if word in text
    )

    if phishing_hits > 0:
        return {
            "score": 95,
            "status": "High Risk",
            "category": "Phishing",
            "explanation": "Possible phishing attempt detected"
        }

    elif fraud_hits > 0:
        return {
            "score": 90,
            "status": "High Risk",
            "category": "Fraud",
            "explanation": "Possible fraud attempt detected"
        }

    elif scam_hits > 0:
        return {
            "score": 85,
            "status": "Suspicious",
            "category": "Scam",
            "explanation": "Potential scam detected"
        }

    return {
        "score": 5,
        "status": "Low Risk",
        "category": "Safe",
        "explanation": "No threats detected"
    }

# =========================
# ALERT SYSTEM
# =========================

def send_email_alert(alert):
    try:
        msg = MIMEText(f"""
High Risk Alert
Message: {alert['message']}
Score: {alert['score']}
Category: {alert['category']}
Time: {alert['time']}
""")

        msg["Subject"] = "SafeChat Alert"
        msg["From"] = ALERT_EMAIL
        msg["To"] = ALERT_EMAIL

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(ALERT_EMAIL, ALERT_PASSWORD)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print("Email error:", e)



    ALERT_LOG.append(alert)
    if len(ALERT_LOG) > 100:
        ALERT_LOG.pop(0)

    if alert["status"] == "High Risk":
        send_email_alert(alert)

# =========================
# WEBSOCKET
# =========================

class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []

        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except:
                dead.append(conn)

        for d in dead:
            self.active_connections.remove(d)


manager = ConnectionManager()

# =========================
# REQUEST MODEL
# =========================

class AnalyzeRequest(BaseModel):
    text: str


def process_threat(message: str):
    raw = analyze_text(message)

    risk = calculate_risk_score(
        raw.get("category", "Unknown"),
        raw.get("score", 0)
    )

    result = {
        "category": raw["category"],
        "score": risk["risk_score"],
        "status": risk["level"],
        "explanation": raw["explanation"]
    }

    update_threat_intelligence(result["category"], result["score"])

    alert = {
        "message": message,
        "status": result["status"],
        "score": result["score"],
        "category": result["category"],
        "time": str(datetime.datetime.now())
    }

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scans (message, category, risk_score, status, user)
        VALUES (?, ?, ?, ?, ?)
    """, (
        message,
        result["category"],
        result["score"],
        result["status"],
        "guest"
    ))

    conn.commit()
    conn.close()

    if result["status"] == "Suspicious":
        create_alert(message, "Warning")
        create_audit_log("Suspicious threat detected", "system")

    elif result["status"] in ["High Risk", "Critical"]:
        create_alert(message, "Critical")

        incident_id = create_incident(
            scan_id=None,
            message=message,
            category=result["category"],
            severity=result["status"]
        )

        create_audit_log("High risk incident created", "system")

        update_incident_status(
            incident_id,
            "ESCALATED",
            notes="Auto-escalated due to risk score"
        )

    asyncio.create_task(manager.broadcast(alert))

    return alert
# =========================
# ANALYZE ENDPOINT
# =========================
def process_threat(message: str):
    raw = analyze_text(message)

    risk = calculate_risk_score(
        raw.get("category", "Unknown"),
        raw.get("score", 0)
    )

    result = {
        "category": raw["category"],
        "score": risk["risk_score"],
        "status": risk["level"],
        "explanation": raw["explanation"]
    }

    update_threat_intelligence(result["category"], result["score"])

    alert = {
        "message": message,
        "status": result["status"],
        "score": result["score"],
        "category": result["category"],
        "time": str(datetime.datetime.now())
    }

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scans (message, category, risk_score, status, user)
        VALUES (?, ?, ?, ?, ?)
    """, (
        message,
        result["category"],
        result["score"],
        result["status"],
        "guest"
    ))

    conn.commit()
    conn.close()

    if result["status"] == "Suspicious":
        create_alert(message, "Warning")
        create_audit_log("Suspicious threat detected", "system")

    elif result["status"] in ["High Risk", "Critical"]:
        create_alert(message, "Critical")

        incident_id = create_incident(
            scan_id=None,
            message=message,
            category=result["category"],
            severity=result["status"]
        )

        create_audit_log("High risk incident created", "system")

        update_incident_status(
            incident_id,
            "ESCALATED",
            notes="Auto-escalated due to risk score"
        )

    # SAFE async broadcast
    asyncio.create_task(manager.broadcast(alert))

    return alert
@app.post("/analyze")
async def analyze(payload: AnalyzeRequest):
    return process_threat(payload.text)
# =========================
# FETCH HELPERS
# =========================

def fetch_recent(limit=50):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# =========================
# STATS
# =========================

def get_threat_stats(rows):
    high = sum(1 for r in rows if r["status"] == "High Risk")
    suspicious = sum(1 for r in rows if r["status"] == "Suspicious")
    low = sum(1 for r in rows if r["status"] == "Low Risk")

    categories = {}
    for r in rows:
        categories[r["category"]] = categories.get(r["category"], 0) + 1

    top_category = max(categories, key=categories.get) if categories else "None"
    threat_level = min(100, (high * 12) + (suspicious * 5))

    return {
        "high": high,
        "suspicious": suspicious,
        "low": low,
        "top_category": top_category,
        "threat_level": threat_level
    }

# =========================
# DASHBOARD
# =========================

@app.get("/dashboard-data")
def dashboard():
    rows = fetch_recent(200)

    stats = get_threat_stats(rows)

    return {
        "total": len(rows),
        "high": stats["high"],
        "suspicious": stats["suspicious"],
        "low": stats["low"]
    }

# =========================
# ALERTS
# =========================

@app.get("/alerts")
def alerts(limit: int = 20):
    return {
        "count": len(ALERT_LOG),
        "data": ALERT_LOG[-limit:]
    }
# =========================
# PDF REPORT
# =========================

@app.get("/pdf-report")
def pdf_report():
    from reportlab.pdfgen import canvas

    rows = fetch_recent(50)

    file = "report.pdf"
    c = canvas.Canvas(file)

    c.drawString(100, 800, "SAFECHAT REPORT")
    c.drawString(100, 780, f"Total: {len(rows)}")

    c.save()

    return FileResponse(file, media_type="application/pdf")

# =========================
# UI (FIXED HTML)
# =========================

@app.get("/ui", response_class=HTMLResponse)
def ui():
    return """
    <html>
    <body style="background:#0b1220;color:white;font-family:Arial;">
        <h2>SafeChat AI</h2>
        <textarea id="msg"></textarea>
        <button onclick="send()">Analyze</button>

        <pre id="out"></pre>

        <script>

async function send() {
    try {
        const text = document.getElementById("msg").value;

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ text })
        });

        if (!response.ok) {
            const err = await response.text();
            document.getElementById("out").innerText =
                "ERROR: " + err;
            return;
        }

        const data = await response.json();

        document.getElementById("out").innerText =
            JSON.stringify(data, null, 2);

    } catch (error) {
        document.getElementById("out").innerText =
            "FETCH ERROR: " + error.message;
    }
}

</script>
    </body>
    </html>
    """
@app.get("/incidents")
def incidents():
    return get_incidents()


@app.get("/incidents/open")
def open_incidents():
    return get_open_incidents()


@app.get("/alerts-db")
def alerts_db():
    return get_alerts()


@app.get("/audit-logs")
def audit_logs():
    return get_audit_logs()

# =========================
# WEBSOCKET
# =========================

@app.websocket("/ws")
async def ws(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
@app.get("/health")
def health():
    return {
        "status": "online",
        "service": "SafeChat AI SOC",
        "database": "connected"
    }

@app.get("/soc-summary")
def soc_summary():

    return {
        "total_scans": get_total_scans(),
        "total_alerts": get_total_alerts(),
        "total_incidents": get_total_incidents(),
        "open_incidents": get_open_incident_count(),
        "status": "operational"
    }
@app.get("/soc", response_class=HTMLResponse)
def soc_dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SafeChat AI SOC</title>

        <style>
            body{
                background:#0b1220;
                color:white;
                font-family:Arial;
                padding:20px;
            }

            h1{
                color:#00d4ff;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(4,1fr);
                gap:15px;
            }

            .card{
                background:#182235;
                padding:20px;
                border-radius:10px;
                text-align:center;
            }

            .number{
                font-size:32px;
                font-weight:bold;
                margin-top:10px;
            }

            .section{
                margin-top:30px;
            }

            table{
                width:100%;
                border-collapse:collapse;
            }

            td,th{
                border:1px solid #333;
                padding:10px;
            }
        </style>
    </head>

    <body>

        <h1>SAFECHAT AI SECURITY OPERATIONS CENTER</h1>

        <div class="grid">

            <div class="card">
                <h3>Total Scans</h3>
                <div id="scans" class="number">0</div>
            </div>

            <div class="card">
                <h3>Total Alerts</h3>
                <div id="alerts" class="number">0</div>
            </div>

            <div class="card">
                <h3>Total Incidents</h3>
                <div id="incidents" class="number">0</div>
            </div>

            <div class="card">
                <h3>Open Incidents</h3>
                <div id="open" class="number">0</div>
            </div>

        </div>

        <div class="section">
            <h2>Recent Alerts</h2>
            <pre id="alertFeed"></pre>
        </div>

        <script>

        async function loadDashboard(){

    const soc =
        await fetch('/soc-summary')
        .then(r => r.json());

    const alerts =
        await fetch('/alerts-db')
        .then(r => r.json());

    document.getElementById('scans').innerText =
        soc.total_scans;

    document.getElementById('alerts').innerText =
        soc.total_alerts;

    document.getElementById('incidents').innerText =
        soc.total_incidents;

    document.getElementById('open').innerText =
        soc.open_incidents;

    document.getElementById('alertFeed').innerText =
        JSON.stringify(alerts.slice(0,10), null, 2);
}
        loadDashboard();

        setInterval(loadDashboard,5000);

        </script>

    </body>
    </html>
    """
@app.get("/intelligence")
def intelligence():

    return {
        "status": "active",
        "data": get_threat_intelligence()
    }
# =========================
# ANALYTICS ENDPOINTS
# =========================

@app.get("/analytics/categories")
def analytics_categories():
    return get_category_distribution()


@app.get("/analytics/kpis")
def analytics_kpis():
    return get_executive_kpis()
@app.post("/incident/update")
def update_incident(incident_id: int, status: str, notes: str = None):
    from db import update_incident_status

    update_incident_status(incident_id, status, notes)

    return {
        "status": "updated",
        "incident_id": incident_id
    }
@app.get("/incidents/status/{status}")
def incidents_by_status(status: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM incidents
        WHERE status = ?
        ORDER BY id DESC
    """, (status,))

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
@app.get("/incidents/lifecycle")
def incident_lifecycle():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT status, COUNT(*) as total
        FROM incidents
        GROUP BY status
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]
from db import init_db

@app.on_event("startup")
def startup():
    init_db()
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()  # keep connection alive
    except:
        manager.disconnect(websocket)