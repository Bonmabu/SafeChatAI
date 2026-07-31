from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

import sqlite3, csv, asyncio
from typing import List

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from reportlab.pdfgen import canvas

# =========================
# APP
# =========================
app = FastAPI()

API_KEY = "safechat-secret-123"

def verify_key(key: str):
    return key == API_KEY


# =========================
# CORS
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# DATABASE
# =========================
conn = sqlite3.connect("scams.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    category TEXT,
    risk_score INTEGER,
    status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()


# =========================
# ML MODEL
# =========================
data = [
    ("send mpesa pin", 1),
    ("click here to claim prize", 1),
    ("investment opportunity returns", 0),
    ("you have won lottery", 1),
    ("meeting tomorrow", 0),
]

X_text = [x[0] for x in data]
y = [x[1] for x in data]

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(X_text)

model = LogisticRegression()
model.fit(X, y)


# =========================
# RULE ENGINE
# =========================
rules = {
    "mpesa": (40, "Mobile Money Scam"),
    "pin": (50, "Phishing Attack"),
    "click here": (35, "Phishing"),
    "investment": (45, "Ponzi Scheme"),
    "lottery": (60, "Fake Winning Scam"),
}


# =========================
# WEBSOCKET MANAGER
# =========================
class ConnectionManager:
    def __init__(self):
        self.clients: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.append(ws)

    def disconnect(self, ws: WebSocket):
        self.clients.remove(ws)

    async def broadcast(self, msg: dict):
        for c in self.clients:
            await c.send_json(msg)


manager = ConnectionManager()


def broadcast_sync(data: dict):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(manager.broadcast(data))
        else:
            loop.run_until_complete(manager.broadcast(data))
    except:
        pass


# =========================
# HOME
# =========================
@app.get("/")
def home():
    return {"status": "SafeChat SOC Running"}


# =========================
# ANALYZE ENGINE
# =========================
@app.get("/analyze")
def analyze(message: str, key: str = ""):

    if not verify_key(key):
        return {"error": "Unauthorized"}

    text = message.lower()

    ml_score = model.predict_proba(vectorizer.transform([text]))[0][1] * 100

    rule_score = 0
    category = "Safe"

    for k, (score, cat) in rules.items():
        if k in text:
            rule_score += score
            category = cat

    final_score = (0.7 * ml_score) + (0.3 * rule_score)

    status = (
        "Low Risk" if final_score < 30 else
        "Suspicious" if final_score < 70 else
        "High Risk"
    )

    cursor.execute("""
        INSERT INTO scans(message, category, risk_score, status)
        VALUES (?, ?, ?, ?)
    """, (message, category, int(final_score), status))
    conn.commit()

    broadcast_sync({
        "message": message,
        "score": final_score,
        "status": status
    })

    return {
        "message": message,
        "score": round(final_score, 2),
        "category": category,
        "status": status
    }


# =========================
# DASHBOARD
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():

    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()

    total = len(rows)
    high = sum(1 for r in rows if r[4] == "High Risk")
    suspicious = sum(1 for r in rows if r[4] == "Suspicious")
    low = sum(1 for r in rows if r[4] == "Low Risk")

    return f"""
    <html>
    <body style="font-family:Arial;background:#0f172a;color:white;padding:20px">

        <h1>SafeChat SOC Dashboard</h1>

        <p>Total: {total}</p>
        <p>High Risk: {high}</p>
        <p>Suspicious: {suspicious}</p>
        <p>Low Risk: {low}</p>

    </body>
    </html>
    """


# =========================
# UI
# =========================
@app.get("/ui", response_class=HTMLResponse)
def ui():
    return """
    <html>
    <body style="font-family:Arial;background:#0f172a;color:white;padding:20px">

    <h1>SafeChat AI Scanner</h1>

    <textarea id="msg" style="width:400px;height:100px"></textarea>
    <br><br>

    <button onclick="run()">Analyze</button>

    <div id="out"></div>

    <script>
    async function run(){
        let msg = document.getElementById("msg").value;

        let res = await fetch("/analyze?message=" + encodeURIComponent(msg) + "&key=safechat-secret-123");
        let data = await res.json();

        document.getElementById("out").innerHTML =
        "Score: " + data.score + "<br>Status: " + data.status;
    }
    </script>

    </body>
    </html>
    """


# =========================
# DASHBOARD DATA
# =========================
@app.get("/dashboard-data")
def dashboard_data():
    cursor.execute("SELECT * FROM scans")
    rows = cursor.fetchall()

    return {
        "total": len(rows),
        "high": sum(1 for r in rows if r[4] == "High Risk"),
        "suspicious": sum(1 for r in rows if r[4] == "Suspicious"),
        "low": sum(1 for r in rows if r[4] == "Low Risk"),
    }


# =========================
# RECENT
# =========================
@app.get("/recent")
def recent():
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")
    return cursor.fetchall()


# =========================
# EXPORT CSV
# =========================
@app.get("/export")
def export():
    cursor.execute("SELECT * FROM scans")
    rows = cursor.fetchall()

    file = "report.csv"
    with open(file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id","message","category","score","status","time"])
        writer.writerows(rows)

    return FileResponse(file)


# =========================
# PDF REPORT
# =========================
@app.get("/pdf-report")
def pdf_report():

    cursor.execute("SELECT * FROM scans")
    rows = cursor.fetchall()

    file = "report.pdf"
    c = canvas.Canvas(file)

    y = 800
    for r in rows[:50]:
        c.drawString(50, y, f"{r[1]} | {r[2]} | {r[3]} | {r[4]}")
        y -= 20

    c.save()
    return FileResponse(file, media_type="application/pdf")


# =========================
# INCIDENT REPORT
# =========================
@app.get("/incident-report")
def incident_report():

    cursor.execute("SELECT * FROM scans WHERE status='High Risk'")
    rows = cursor.fetchall()

    return {
        "total": len(rows),
        "incidents": rows
    }


# =========================
# HEALTH
# =========================
@app.get("/health")
def health():
    return {"status": "ok"}


# =========================
# WEBSOCKET
# =========================
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)