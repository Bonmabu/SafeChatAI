from fastapi import (
    FastAPI,
    Header,
    Request,
    WebSocket,
    WebSocketDisconnect,
    Depends
)
from event_correlation import (
    init_event_correlation,
    correlate_event,
    get_event_correlations,
    get_correlation_cluster,
    get_correlation_clusters,
    get_attack_campaign,
    get_attack_campaigns,
    get_campaign_timeline,
)
from security_fabric import (
    init_security_fabric,
    persist_security_event,
    get_security_events,
    get_security_event,
)
from replay_engine import add_replay_event, get_replay
from attack_graph import add_event, get_graph
from fastapi.responses import FileResponse
from correlation import get_campaigns as correlation_get_campaigns
from passlib.context import CryptContext
from ai.soc_brain import executive_reasoning
from io import BytesIO
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from dotenv import load_dotenv
import os
import logging

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("SafeChatAI")
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from ai.threat_intel import enrich_iocs
from ai.threat_intel import enrich_incident
from ai.threat_intel import analyze_iocs
from ai.copilot import soc_copilot
from collections import Counter
from ai.campaign import detect_campaign as ai_detect_campaign
from ai.correlation import correlate_incidents
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security
from uuid import uuid4
from pydantic import BaseModel
from fastapi.responses import StreamingResponse
from fastapi.responses import JSONResponse
import json
import time
import csv
from reportlab.platypus import SimpleDocTemplate, Table
from threading import Thread
from prediction_engine import learn, predict
from kill_chain import analyze_kill_chain
from sklearn.linear_model import LinearRegression
from campaign_engine import detect_campaign as engine_detect_campaign, get_campaigns as engine_get_campaigns
from ai.soc_brain import (
    analyze_pattern,
    predict_next_attack,
    executive_reasoning,
)
class LoginRequest(BaseModel):
    username: str
    password: str

import asyncio
import re
import numpy as np
import threading
import random
EVENT_STREAM = {
    "raw_events": [],
    "alerts": [],
    "incidents": [],
    "processed_events": [],
    "executive": []
}
LAST_CORRELATION_ID = None

ATTACK_TIMELINE = {}

LOCK = threading.Lock()

from sklearn.ensemble import IsolationForest
MODEL = IsolationForest(contamination=0.05)
from db import create_scan

from db import (
    init_db,
    db_sql,
    get_conn,
    create_incident,
    update_incident_status,
    get_incidents,
    get_audit_logs,
    get_risk_score,
    get_top_threat,
    get_daily_threats,
    get_weekly_threats,
    get_executive_kpis,
    get_category_distribution,
    get_risk_heatmap,
    get_total_scans,
    get_total_alerts,
    get_total_incidents,
    get_open_incident_count,
    get_threat_trends,
    get_threat_velocity,
    get_threat_anomaly_score,
    get_soc_intelligence_core,
    save_threat_hunt,
    upsert_threat_intelligence,
    get_threat_intelligence,
    create_alert,
    assign_incident,
    save_threat_ioc,
    add_threat_intel_column,
    save_incident,
    get_executive_threat_map
)
# =========================
# APPLICATION CONFIGURATION
# =========================

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing.")

DATABASE_PATH = os.getenv("DATABASE_PATH", "scams.db")

FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "http://localhost:5173"
)

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
EXECUTIVE_PASSWORD = os.getenv("EXECUTIVE_PASSWORD")
ANALYST_PASSWORD = os.getenv("ANALYST_PASSWORD")
CUSTOMER_PASSWORD = os.getenv("CUSTOMER_PASSWORD")
VIEWER_PASSWORD = os.getenv("VIEWER_PASSWORD")

# =========================
# APP INIT
# =========================

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "https://safechatai-1.onrender.com",
    FRONTEND_URL,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

init_db()


@app.get("/status")
def status():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM scans")
    scans = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts")
    alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM incidents")
    incidents = cur.fetchone()[0]

    conn.close()

    return {
        "server": "online",
        "database": "connected",
        "scans": scans,
        "alerts": alerts,
        "incidents": incidents
    }


active_connections = []

from fastapi.openapi.utils import get_openapi
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="SOC SIEM API",
        version="1.0",
        description="Enterprise SOC System",
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            openapi_schema["paths"][path][method]["security"] = [
                {"BearerAuth": []}
            ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

# =========================
# GLOBAL STATE
# =========================

API_KEY = os.getenv("API_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440)
)
# ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â PHASE 9 AUTH SYSTEM
INCIDENT_DECLARED = False
CRISIS_MODE = False
ACTIVE_SESSIONS = {}
ALERT_LOG = []
USER_ROLES = {
    "admin": ["read", "write", "delete", "analyze"],
    "analyst": ["read", "analyze"],
    "viewer": ["read"]
}
def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )

# =========================
# CONNECTION MANAGER
# =========================

def check_permission(role: str, action: str):
    return action in USER_ROLES.get(role, [])
    EXECUTIVE_EVENTS = []


def add_executive_event(event_type, message, severity="INFO"):
    event = {
        "type": event_type,
        "message": message,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat()
    }

    EXECUTIVE_EVENTS.insert(0, event)

    # keep latest 100 events
    if len(EXECUTIVE_EVENTS) > 100:
        EXECUTIVE_EVENTS.pop()

    return event


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
        print("ÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã‚Â¡ BROADCAST CALLED")
        print("ÃƒÂ°Ã…Â¸Ã¢â‚¬ËœÃ‚Â¥ CONNECTIONS:", len(self.active_connections))

        dead = []

        for connection in self.active_connections:
            try:
                await connection.send_json(message)

            except Exception as e:
                print("ÃƒÂ¢Ã‚ÂÃ…â€™ SEND FAILED:", e)
                dead.append(connection)

        for d in dead:
            self.disconnect(d)


manager = ConnectionManager()


# =====================================================
# Global broadcast wrapper
# Used by Executive War Room actions
# =====================================================

async def broadcast(event):
    await manager.broadcast(event)

ATTACK_CORRELATION = {}
ATTACK_TIMELINE = {}

ATTACK_GRAPH = {
    "nodes": {},
    "edges": [],
    "clusters": {},
    "last_node": None
}
LAST_ATTACK_NODE = None
ACTIVE_INCIDENTS = {}

IOC_DATABASE = {
    "ips": {},
    "domains": {},
    "emails": {},
    "urls": {},
    "hashes": {}
}
THREAT_INTELLIGENCE = {
    "ioc": {},
    "campaigns": {},
    "actors": {},
    "malware": {}
}
# =====================================================
# Global broadcast wrapper for executive actions
# =====================================================

async def broadcast(event):
    await manager.broadcast(event)
def ensure_timeline(corr_id: str):
    if corr_id not in ATTACK_TIMELINE:
        ATTACK_TIMELINE[corr_id] = []
EVENT_STREAM = {
    "raw_events": [],
    "processed_events": [],
    "alerts": [],
    "incidents": [],
    "executive": []
}
SOC_MEMORY = {
    "recent_incidents": [],
    "threat_patterns": {},
    "learned_behaviors": {}
}
SOC_REASONING_STATE = {
    "last_decisions": [],
    "risk_bias": 1.0,
    "auto_tuning": True
}
THREAT_PREDICTION = {
    "predictions": [],
    "models": {},
    "confidence": 0
}

def update_soc_memory(category: str, score: float, corr_id: str):

    # -------------------------
    # TRACK INCIDENT PATTERNS
    # -------------------------
    if category not in SOC_MEMORY["threat_patterns"]:
        SOC_MEMORY["threat_patterns"][category] = {
            "count": 0,
            "avg_score": 0
        }

    pattern = SOC_MEMORY["threat_patterns"][category]

    pattern["count"] += 1
    pattern["avg_score"] = (
        (pattern["avg_score"] * (pattern["count"] - 1) + score)
        / pattern["count"]
    )

    # -------------------------
    # RECENT INCIDENT BUFFER
    # -------------------------
    SOC_MEMORY["recent_incidents"].append({
        "category": category,
        "score": score,
        "corr_id": corr_id,
        "timestamp": now_ts()
    })

    # KEEP ONLY LAST 50
    if len(SOC_MEMORY["recent_incidents"]) > 50:
        SOC_MEMORY["recent_incidents"] = SOC_MEMORY["recent_incidents"][-50:]

    # -------------------------
    # LEARNING RULE
    # -------------------------
    if pattern["count"] > 5 and pattern["avg_score"] > 75:
        SOC_MEMORY["learned_behaviors"][category] = {
            "risk_level": "PERSISTENT_THREAT",
            "auto_escalate": True
        }

def build_event(event_type: str, payload: dict):
    return {
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "source": "safechat_soc_engine",
        "version": "4.7.9",
        "data": payload
    }
async def push_event(event_type: str, payload: dict):

    event = build_event(event_type, payload)

    validate_event(event)

    # -------------------------
    # EVENT ROUTING MAP
    # -------------------------
    EVENT_MAP = {
        "scan_event": "raw_events",
        "alert_event": "alerts",
        "incident_event": "incidents",
        "auto_response_event": "processed_events",
        "executive_dashboard": "executive"
    }

    bucket = EVENT_MAP.get(event_type, "raw_events")

    if bucket not in EVENT_STREAM:
        EVENT_STREAM[bucket] = []

    EVENT_STREAM[bucket].append(event)

    # -------------------------
    # SPECIAL ALERT HANDLING
    # -------------------------
    if event_type == "alert_event":
        if "alerts" not in EVENT_STREAM:
            EVENT_STREAM["alerts"] = []
        EVENT_STREAM["alerts"].append(event)

    # -------------------------
    # RAW EVENT STORE (SIEM LAYER)
    # -------------------------
    if "raw_events" not in EVENT_STREAM:
        EVENT_STREAM["raw_events"] = []

    EVENT_STREAM["raw_events"].append(event)

    # -------------------------
    # BROADCAST
    # -------------------------
    await manager.broadcast(event)

    # -------------------------
    # SOC FILTERED ALERTS
    # -------------------------
    if event_type in ["incident_event", "auto_response_event"]:
        print(f"[SOC ALERT] {event_type} triggered")
def validate_event(payload: dict):

    required_fields = [
        "event_type",
        "timestamp",
        "source",
        "data"
    ]

    for field in required_fields:
        if field not in payload:
            raise ValueError(
                f"Missing required field: {field}"
            )

    if not isinstance(payload["data"], dict):
        raise ValueError(
            "Event data must be a dictionary"
        )

    return True
def get_user_from_token(token: str):

    return ACTIVE_SESSIONS.get(token)
# =========================
# THREAT CLASSIFIER
# =========================

def classify_threat(text: str):
    t = text.lower()

    THREAT_SIGNATURES = {

        "Business Email Compromise": {
            "score": 96,
            "stage": "Initial Access",
            "mitre": "T1566.002 - Spearphishing Link",
            "keywords": [
                "wire transfer",
                "invoice fraud",
                "ceo fraud",
                "urgent payment",
                "payment request",
                "gift cards",
                "vendor payment",
                "change bank account",
                "finance department"
            ]
        },

        "Cloud Compromise": {
            "score": 98,
            "stage": "Initial Access",
            "mitre": "T1078 - Valid Accounts",
            "keywords": [
                "cloudtrail",
                "guardduty",
                "createaccesskey",
                "iam",
                "sts",
                "assumerole",
                "root account",
                "access key",
                "mfa disabled",
                "aws",
                "azure",
                "gcp",
                "cloud security",
                "s3 bucket",
                "public bucket"
            ]
        },

        "Identity Attack": {
            "score": 95,
            "stage": "Credential Access",
            "mitre": "T1078 - Valid Accounts",
            "keywords": [
                "impossible travel",
                "conditional access",
                "azure ad",
                "entra",
                "identity",
                "mfa bypass",
                "login from",
                "session remains active",
                "credential stuffing"
            ]
        },

        "Password Spraying": {
            "score": 95,
            "stage": "Credential Access",
            "mitre": "T1110.003 - Password Spraying",
            "keywords": [
                "password spraying",
                "multiple authentication failures",
                "attempted against",
                "same password",
                "user accounts"
            ]
        },

        "Brute Force": {
            "score": 94,
            "stage": "Credential Access",
            "mitre": "T1110.001 - Password Guessing",
            "keywords": [
                "failed login",
                "failed logon",
                "authentication failure",
                "account locked",
                "login attempts",
                "too many login attempts"
            ]
        },

        "Container Attack": {
            "score": 95,
            "stage": "Privilege Escalation",
            "mitre": "T1611 - Container Escape",
            "keywords": [
                "kubernetes",
                "cluster-admin",
                "container escape",
                "namespace",
                "pod",
                "/bin/sh",
                "docker",
                "kubectl",
                "privileged container"
            ]
        },

        "Privilege Escalation": {
            "score": 97,
            "stage": "Privilege Escalation",
            "mitre": "T1068 - Exploitation for Privilege Escalation",
            "keywords": [
                "system privileges",
                "administrator account",
                "local administrator",
                "privilege escalation",
                "elevated privileges",
                "added to administrators",
                "sudo"
            ]
        },

        "Lateral Movement": {
            "score": 97,
            "stage": "Lateral Movement",
            "mitre": "T1021 - Remote Services",
            "keywords": [
                "psexec",
                "remote service",
                "remote service creation",
                "smb",
                "admin shares",
                "wmic",
                "remote desktop",
                "lateral movement"
            ]
        },

        "Active Directory Attack": {
            "score": 99,
            "stage": "Credential Access",
            "mitre": "T1558 - Steal or Forge Kerberos Tickets",
            "keywords": [
                "golden ticket",
                "pass-the-ticket",
                "kerberos",
                "lsass",
                "mimikatz",
                "domain administrator",
                "dcsync"
            ]
        },

        "Command & Control": {
            "score": 97,
            "stage": "Command and Control",
            "mitre": "T1071 - Application Layer Protocol",
            "keywords": [
                "c2",
                "beacon",
                "beacon interval",
                "known c2",
                "reverse shell",
                "outbound connection",
                "command and control"
            ]
        },

        "DNS Tunneling": {
            "score": 96,
            "stage": "Command and Control",
            "mitre": "T1071.004 - DNS",
            "keywords": [
                "dns tunneling",
                "txt requests",
                "encoded traffic",
                "dns exfiltration",
                "large dns requests"
            ]
        },

        "Web Shell": {
            "score": 97,
            "stage": "Persistence",
            "mitre": "T1505.003 - Web Shell",
            "keywords": [
                "cmd.aspx",
                "web shell",
                "iis",
                "whoami",
                "shell uploaded"
            ]
        },

        "Malware": {
            "score": 90,
            "stage": "Execution",
            "mitre": "T1204 - User Execution",
            "keywords": [
                "powershell",
                "malware",
                "trojan",
                "virus",
                "loader",
                "dropper",
                "payload",
                "shellcode"
            ]
        },

        "Crypto Mining": {
            "score": 90,
            "stage": "Execution",
            "mitre": "T1496 - Resource Hijacking",
            "keywords": [
                "xmrig",
                "mining pool",
                "cryptocurrency miner",
                "coinminer",
                "monero",
                "cpu utilization"
            ]
        },

        "Supply Chain Attack": {
            "score": 98,
            "stage": "Initial Access",
            "mitre": "T1195 - Supply Chain Compromise",
            "keywords": [
                "software update",
                "trusted vendor",
                "signed package",
                "supply chain",
                "malicious update",
                "compromised vendor"
            ]
        },

        "SQL Injection": {
            "score": 90,
            "stage": "Initial Access",
            "mitre": "T1190 - Exploit Public Facing Application",
            "keywords": [
                "' or 1=1",
                "union select",
                "sql injection",
                "/login",
                "database errors"
            ]
        },

        "Cross Site Scripting": {
            "score": 88,
            "stage": "Initial Access",
            "mitre": "T1190 - Exploit Public Facing Application",
            "keywords": [
                "<script>",
                "xss",
                "javascript:",
                "onerror=",
                "alert("
            ]
        },

        "Phishing": {
            "score": 85,
            "stage": "Initial Access",
            "mitre": "T1566 - Phishing",
            "keywords": [
                "password",
                "verify account",
                "otp",
                "login",
                "bank",
                "email",
                "attachment",
                "click here",
                "excel"
            ]
        },

        "Data Exfiltration": {
            "score": 97,
            "stage": "Exfiltration",
            "mitre": "T1048 - Exfiltration Over Alternative Protocol",
            "keywords": [
                "dropbox",
                "uploaded",
                "customer records",
                "onedrive",
                "google drive",
                "sensitive data"
            ]
        },

        "Data Leak": {
            "score": 95,
            "stage": "Exfiltration",
            "mitre": "T1020 - Automated Exfiltration",
            "keywords": [
                "pastebin",
                "mega.nz",
                "telegram upload",
                "discord upload",
                "github gist",
                "source code leak",
                "confidential documents"
            ]
        },

        "Insider Threat": {
            "score": 92,
            "stage": "Exfiltration",
            "mitre": "T1020 - Automated Exfiltration",
            "keywords": [
                "usb",
                "employee",
                "copied files",
                "after business hours",
                "endpoint protection"
            ]
        },

        "Insider Sabotage": {
            "score": 97,
            "stage": "Impact",
            "mitre": "T1485 - Data Destruction",
            "keywords": [
                "deleted database",
                "deleted backups",
                "destroyed files",
                "wiped server",
                "rm -rf"
            ]
        },

        "Ransomware": {
            "score": 100,
            "stage": "Impact",
            "mitre": "T1486 - Data Encrypted for Impact",
            "keywords": [
                ".locked",
                "encrypting files",
                "vssadmin",
                "delete shadows",
                "shadow copies",
                "ransom note",
                "ransomware"
            ]
        },

        "AI Prompt Injection": {
            "score": 95,
            "stage": "Defense Evasion",
            "mitre": "T1562 - Impair Defenses",
            "keywords": [
                "ignore previous instructions",
                "system prompt",
                "reveal confidential data",
                "bypass safety",
                "execute hidden commands",
                "prompt injection"
            ]
        },

        "Harassment": {
            "score": 75,
            "stage": "Impact",
            "mitre": "T1499 - Endpoint Denial of Service",
            "keywords": [
                "kill",
                "die",
                "shoot",
                "bomb",
                "stab",
                "murder",
                "terrorist",
                "i will kill you",
                "i'm going to kill you"
            ]
        }

    }

    matches = []

    for category, data in THREAT_SIGNATURES.items():

        hits = 0

        for keyword in data["keywords"]:
            if keyword.lower() in t:
                hits += 1

        if hits == 0:
            continue

        score = min(100, data["score"] + hits)

        matches.append({
            "category": category,
            "score": score,
            "stage": data["stage"],
            "mitre": data["mitre"],
            "confidence": min(99, score),
            "hits": hits
        })

    if matches:

        matches.sort(key=lambda x: (x["score"], x["hits"]), reverse=True)

        primary = matches[0]

        return (
            primary["category"],
            primary["score"],
            primary["stage"],
            primary["mitre"],
            primary["confidence"],
            matches
        )

    return (
        "Safe",
        10,
        "None",
        "None",
        99,
        []
    )
# =========================
# MITRE ATT&CK MAPPING
# =========================

MITRE_ATTACK = {
    "Phishing": {
        "tactic": "Initial Access",
        "technique": "T1566",
        "name": "Phishing"
    },

    "Malware": {
        "tactic": "Execution",
        "technique": "T1204",
        "name": "User Execution"
    },

    "Fraud": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "name": "Brute Force"
    },

    "Harassment": {
        "tactic": "Impact",
        "technique": "T1499",
        "name": "Endpoint Denial of Service"
    },

    "Safe": {
        "tactic": "None",
        "technique": "-",
        "name": "No Mapping"
    }
}


def mitre_lookup(category: str):
    return MITRE_ATTACK.get(
        category,
        MITRE_ATTACK["Safe"]
    )
import hashlib

def generate_correlation_key(category: str, message: str):
    base = f"{category}:{message}"
    return hashlib.md5(base.encode()).hexdigest()[:12]


def now_ts():
    return datetime.utcnow().isoformat()


def add_graph_node(node_id, category, score, stage=None, mitre=None):
    global ATTACK_GRAPH

    ATTACK_GRAPH["nodes"][node_id] = {
        "id": node_id,
        "category": category,
        "max_score": score,
        "stage": stage,
        "mitre": mitre,
        "count": 1
    }

    ATTACK_GRAPH["last_node"] = node_id

    return ATTACK_GRAPH
def add_graph_edge(source: str, target: str, category="CORRELATED_ATTACK"):

    global ATTACK_GRAPH

    if not source or not target:
        return

    if source == target:
        return


    # Ensure nodes structure
    if isinstance(ATTACK_GRAPH.get("nodes"), list):
        ATTACK_GRAPH["nodes"] = {
            n["id"]: n
            for n in ATTACK_GRAPH["nodes"]
        }


    # Create source node if missing
    if source not in ATTACK_GRAPH["nodes"]:
        ATTACK_GRAPH["nodes"][source] = {
            "id": source,
            "category": source,
            "max_score": 50,
            "count": 1
        }


    # Create target node if missing
    if target not in ATTACK_GRAPH["nodes"]:
        ATTACK_GRAPH["nodes"][target] = {
            "id": target,
            "category": target,
            "max_score": 50,
            "count": 1
        }


    # Check duplicate edge
    for edge in ATTACK_GRAPH["edges"]:

        if (
            edge["source"] == source
            and edge["target"] == target
        ):
            edge["weight"] = edge.get("weight",1) + 1
            edge["timestamp"] = now_ts()
            return


    # Add new edge
    ATTACK_GRAPH["edges"].append({

        "source": source,
        "target": target,
        "relationship": "CORRELATED_ATTACK",
        "category": category,
        "weight": 1,
        "timestamp": now_ts()

    })


    # Limit graph size
    if len(ATTACK_GRAPH["edges"]) > 500:
        ATTACK_GRAPH["edges"] = ATTACK_GRAPH["edges"][-500:]
def extract_iocs(text):

    ips = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )

    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    domains = re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}\b",
        text
    )

    hashes = re.findall(
        r"\b[a-fA-F0-9]{32,64}\b",
        text
    )

    return {
        "ips": ips,
        "emails": emails,
        "urls": urls,
        "domains": domains,
        "hashes": hashes
    }
def update_ioc_database(iocs):

    conn = get_conn()
    cursor = conn.cursor()

    for category in iocs:

        for value in iocs[category]:

            # Update memory
            if value not in IOC_DATABASE[category]:
                IOC_DATABASE[category][value] = {"count": 1}
            else:
                IOC_DATABASE[category][value]["count"] += 1

            # Update database
            cursor.execute("""
                SELECT id, sightings
                FROM threat_intelligence
                WHERE indicator=?
            """, (value,))

            row = cursor.fetchone()

            if row:

                cursor.execute("""
                    UPDATE threat_intelligence
                    SET sightings=sightings+1,
                        last_seen=datetime('now')
                    WHERE id=?
                """, (row["id"],))

                cursor.execute("""
                    SELECT *
                    FROM threat_intelligence
                    WHERE id=?
                """, (row["id"],))

                data = dict(cursor.fetchone())

            else:

                cursor.execute("""
                    INSERT INTO threat_intelligence
                    (
                        indicator,
                        category,
                        score,
                        confidence,
                        sightings,
                        campaign,
                        first_seen,
                        last_seen
                    )
                    VALUES
                    (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                """, (
                    value,
                    category.title(),
                    85,
                    90,
                    1,
                    "Unknown"
                ))

                conn.commit()

                cursor.execute("""
                    SELECT *
                    FROM threat_intelligence
                    WHERE id=last_insert_rowid()
                """)

                data = dict(cursor.fetchone())

                        # Broadcast live IOC
            import asyncio

            asyncio.create_task(
                manager.broadcast({
                    "type": "ioc_update",
                    "data": data
                })
            )

    conn.commit()
    conn.close()

def update_threat_intelligence(category, text, score):

    global THREAT_INTELLIGENCE

    indicator = category.lower()

    if indicator not in THREAT_INTELLIGENCE["ioc"]:

        THREAT_INTELLIGENCE["ioc"][indicator] = {
            "count": 0,
            "highest_score": score,
            "last_seen": datetime.utcnow().isoformat()
        }

    intel = THREAT_INTELLIGENCE["ioc"][indicator]

    intel["count"] += 1
    intel["highest_score"] = max(
        intel["highest_score"],
        score
    )
    intel["last_seen"] = datetime.utcnow().isoformat()

    return intel
def calculate_status(score: float):
    if score >= 80:
        return "High Risk"
    elif score >= 50:
        return "Suspicious"
    return "Low Risk"

        
# =========================
# CORE SOC ENGINE (SINGLE SOURCE OF TRUTH)
# =========================
def predict_breach_risk():

    data = soc_metrics()

    # -------------------------
    # FEATURE EXTRACTION
    # -------------------------
    risk = data["avg_risk"]
    incidents = data["open_incidents"]
    alerts = data["total_alerts"]
    critical = data["critical_threats"]

    # -------------------------
    # SIMPLE FORECAST MODEL (HEURISTIC PREDICTOR)
    # -------------------------
    risk_trend = (risk * 0.5) + (incidents * 2) + (alerts * 0.2) + (critical * 3)

    # normalize to 0ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“100 scale
    forecast_score = min(100, risk_trend)

    # -------------------------
    # BREACH PROBABILITY
    # -------------------------
    if forecast_score >= 75:
        probability = "HIGH"
        window = "0ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“24 HOURS"
    elif forecast_score >= 50:
        probability = "MEDIUM"
        window = "1ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“3 DAYS"
    elif forecast_score >= 25:
        probability = "LOW"
        window = "3ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“7 DAYS"
    else:
        probability = "MINIMAL"
        window = "STABLE"

    # -------------------------
    # TREND DIRECTION (SIMPLE MODEL)
    # -------------------------
    if risk > 70 and incidents > 5:
        trend = "ESCALATING"
    elif risk < 30:
        trend = "DECREASING"
    else:
        trend = "STABLE"

    return {
        "forecast_score": round(forecast_score, 2),
        "breach_probability": probability,
        "time_window": window,
        "trend": trend
    }
def soc_decision_engine(category: str, score: float, corr_id: str):

    decision = {
        "level": "NONE",
        "actions": [],
        "escalation": False
    }

    # ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â´ CRITICAL THREAT
    if score >= 90:
        decision["level"] = "CRITICAL"
        decision["actions"] = [
            "IMMEDIATE CONTAINMENT",
            "ISOLATE SESSION",
            "TRIGGER INCIDENT RESPONSE TEAM"
        ]
        decision["escalation"] = True

    # ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â  HIGH THREAT
    elif score >= 80:
        decision["level"] = "HIGH"
        decision["actions"] = [
            "AUTO CREATE INCIDENT",
            "ENHANCED MONITORING",
            "LIMIT ACCESS"
        ]
        decision["escalation"] = True

    # ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â¡ MEDIUM
    elif score >= 50:
        decision["level"] = "MEDIUM"
        decision["actions"] = [
            "LOG INCIDENT",
            "MONITOR BEHAVIOR"
        ]

    # ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â¢ LOW
    else:
        decision["level"] = "LOW"
        decision["actions"] = ["LOG ONLY"]

    ATTACK_TIMELINE[corr_id].append({
        "type": "ai_decision",
        "timestamp": now_ts(),
        "decision": decision
    })

    return decision
def auto_response_engine(category: str, score: float, corr_id: str):

    actions = []

    # ---------------- HIGH RISK AUTO RESPONSE ----------------
    if score >= 80:
        actions.append("BLOCK SOURCE IMMEDIATELY")
        actions.append("ESCALATE TO SOC LEVEL 2")
        actions.append("ISOLATE SESSION")

        ensure_timeline(corr_id)
        ATTACK_TIMELINE[corr_id].append({
            "type": "auto_response",
            "action": "BLOCK + ISOLATE",
            "severity": "CRITICAL",
            "timestamp": now_ts()
        })

    # ---------------- MEDIUM RISK ----------------
    elif score >= 50:
        actions.append("INCREASE MONITORING")
        actions.append("FLAG FOR ANALYST REVIEW")

        ensure_timeline(corr_id)
        ATTACK_TIMELINE[corr_id].append({
            "type": "auto_response",
            "action": "MONITORING MODE",
            "severity": "MEDIUM",
            "timestamp": now_ts()
        })

    # ---------------- LOW RISK ----------------
    else:
        actions.append("LOG ONLY")

    return {
        "category": category,
        "score": score,
        "actions": actions
    }


def soc_metrics():

    conn = get_conn()
    cur = conn.cursor()

    # -------------------------
    # CORE COUNTS
    # -------------------------
    cur.execute("SELECT COUNT(*) FROM scans")
    scans = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM alerts")
    alerts = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM incidents")
    incidents = cur.fetchone()[0] or 0

    cur.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status = 'OPEN'
    """)
    open_incidents = cur.fetchone()[0] or 0

    # -------------------------
    # RISK ENGINE
    # -------------------------
    cur.execute("SELECT AVG(risk_score) FROM scans")
    avg_risk = cur.fetchone()[0]

    try:
        avg_risk = float(avg_risk or 0)
    except:
        avg_risk = 0

    avg_risk = round(avg_risk, 2)

    # -------------------------
    # CRITICAL THREATS
    # -------------------------
    cur.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE risk_score >= 80
    """)
    critical_threats = cur.fetchone()[0] or 0

    conn.close()

    # -------------------------
    # NORMALIZATION LAYER
    # -------------------------
    norm_risk = min(avg_risk, 100)
    norm_alerts = min(alerts, 200)
    norm_incidents = min(open_incidents, 50)
    norm_critical = min(critical_threats, 100)

    # -------------------------
    # SOC HEALTH ENGINE
    # -------------------------
    risk_penalty = norm_risk * 0.4
    incident_penalty = norm_incidents * 2.0
    alert_penalty = norm_alerts * 0.3
    critical_penalty = norm_critical * 2.5

    soc_health = 100 - (
        risk_penalty +
        incident_penalty +
        alert_penalty +
        critical_penalty
    )

    soc_health = max(5, min(100, soc_health))

    # -------------------------
    # STATUS CLASSIFICATION
    # -------------------------
    if soc_health >= 75:
        status = "HEALTHY"
    elif soc_health >= 50:
        status = "STABLE"
    elif soc_health >= 25:
        status = "DEGRADED"
    else:
        status = "CRITICAL"

    return {
    "total_scans": scans,
    "total_alerts": alerts,
    "total_incidents": incidents,
    "open_incidents": open_incidents,
    "avg_risk": avg_risk,
    "critical_threats": critical_threats,

    # Frontend expects this
    "security_score": round(soc_health, 2),

    # Keep this too
    "soc_health": round(soc_health, 2),

    "status": status
}
def train_threat_model():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT risk_score FROM scans")
    rows = cur.fetchall()

    conn.close()

    if len(rows) < 10:
        return None

    data = [[r["risk_score"]] for r in rows]

    MODEL.fit(data)

    return MODEL
def predict_threat_anomaly(score: float):

    try:
        result = MODEL.predict([[score]])

        if result[0] == -1:
            return "ANOMALY DETECTED"
        return "NORMAL"

    except:
        return "MODEL NOT TRAINED"
def compute_soc_health(
    risk_score,
    open_incidents,
    critical_alerts
):
    health = 100

    health -= risk_score * 0.5
    health -= open_incidents * 2
    health -= critical_alerts * 3

    return max(0, min(100, health))
def executive_ai_layer():
    data = soc_metrics()

    tpi = (
        data["critical_threats"] * 4 +
        data["open_incidents"] * 3 +
        data["total_alerts"] * 0.2
    )

    instability = min(100, tpi / 2)

    if instability > 70:
        decision = "LOCKDOWN MODE"
    elif instability > 40:
        decision = "HEIGHTENED MONITORING"
    else:
        decision = "NORMAL OPERATIONS"

    return {
        "threat_pressure_index": round(tpi, 2),
        "instability_score": round(instability, 2),
        "executive_decision": decision
    }
def soc_ai_analyst(query: str):

    query = query.lower()

    metrics = soc_metrics()

    insights = []

    # -----------------------------
    # Executive Summary
    # -----------------------------
    insights.append(
        f"{metrics['open_incidents']} open incidents currently require attention."
    )

    insights.append(
        f"Average platform risk score is {metrics['avg_risk']}."
    )

    insights.append(
        f"{metrics['critical_threats']} critical threats have been detected."
    )

    # -----------------------------
    # Threat Pattern Analysis
    # -----------------------------
    if SOC_MEMORY["threat_patterns"]:

        top = max(
            SOC_MEMORY["threat_patterns"].items(),
            key=lambda x: x[1]["count"]
        )

        insights.append(
            f"Most frequent attack category: {top[0]} ({top[1]['count']} detections)."
        )

    # -----------------------------
    # Trend
    # -----------------------------
    if metrics["open_incidents"] > 20:
        insights.append(
            "Incident volume is increasing rapidly."
        )
    else:
        insights.append(
            "Incident volume remains stable."
        )

    # -----------------------------
    # Recommendations
    # -----------------------------
    recommendations = []

    if metrics["critical_threats"] > 0:
        recommendations.append(
            "Investigate all critical incidents immediately."
        )

    if metrics["avg_risk"] > 70:
        recommendations.append(
            "Enable enhanced monitoring across the platform."
        )

    if metrics["open_incidents"] > 10:
        recommendations.append(
            "Assign additional analysts to reduce backlog."
        )

    if not recommendations:
        recommendations.append(
            "Continue normal SOC monitoring."
        )

    return {
        "query": query,
        "insights": insights,
        "recommendations": recommendations,
        "risk_level": metrics["status"],
        "timestamp": datetime.utcnow().isoformat()
    }
def build_threat_matrix():
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "matrix": []
    }

def build_digital_twin():
    return {
        "nodes": list(ATTACK_GRAPH["nodes"].values()),
        "links": ATTACK_GRAPH["edges"]
    }

def build_executive_payload():
    data = soc_metrics()
    ai = executive_ai_layer()

    conn = get_conn()
    cursor = conn.cursor()

    # Active threats
    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status='OPEN'
    """)
    active_threats = cursor.fetchone()[0]

    # Critical alerts
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE risk_score >= 90
    """)
    critical_alerts = cursor.fetchone()[0]

    # Blocked attacks
    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status='BLOCKED'
    """)
    blocked_attacks = cursor.fetchone()[0]

    conn.close()

    return {
        "type": "executive_dashboard",
        "timestamp": datetime.utcnow().isoformat(),

        "kpis": {
            "scans": data["total_scans"],
            "alerts": data["total_alerts"],
            "incidents": data["total_incidents"],
            "open_incidents": data["open_incidents"],

            # NEW
            "active_threats": active_threats,
            "critical_alerts": critical_alerts,
            "blocked_attacks": blocked_attacks,
            "ai_decisions": ai.get("executive_decision", "N/A")
        },

        "risk": {
            "risk_score": data["avg_risk"],
            "critical_threats": data["critical_threats"]
        },

        "soc": {
            "health": data["soc_health"],
            "status": data["status"]
        },
        "security_posture": build_security_posture(),
        "mitre_matrix": build_mitre_matrix(),
        "digital_twin": build_enterprise_digital_twin(),

        "intelligence": {
            "velocity": get_threat_velocity(),
            "anomaly": get_threat_anomaly_score(),
            "forecast": predict_breach_risk()
        },

        "attack_burst": detect_attack_burst(),

        "ai": ai,

"executive_briefing": {
    "title": "Enterprise AI Assessment",

    "summary":
        f"Enterprise risk score is {data['avg_risk']:.2f}. "
        f"{data['critical_threats']} critical threats remain active. "
        f"SOC health is {data['status']}. "
        f"AI recommends {ai['executive_decision']}.",

    "priority":
        "HIGH"
        if data["critical_threats"] > 0
        else "NORMAL",

    "recommendations": [
        "Investigate critical incidents immediately.",
        "Increase monitoring on internet-facing assets.",
        "Validate identity systems for compromise.",
        "Review executive response plan."
    ]
},
    }
def build_security_posture():
    data = soc_metrics()
    forecast = predict_breach_risk()

    security_score = max(0, 100 - data["avg_risk"])

    if security_score >= 80:
        level = "LOW"
        color = "#22c55e"
    elif security_score >= 60:
        level = "GUARDED"
        color = "#facc15"
    elif security_score >= 40:
        level = "HIGH"
        color = "#f97316"
    else:
        level = "CRITICAL"
        color = "#ef4444"

    protected_assets = (
        data["total_scans"]
        - data["critical_threats"]
    )

    return {
        "security_score": round(security_score, 1),
        "threat_level": level,
        "active_incidents": data["open_incidents"],
        "protected_assets": max(0, protected_assets),
        "risk_prediction": forecast.get("breach_probability", "UNKNOWN"),
        "critical_threats": data["critical_threats"],
        "soc_health": data["soc_health"],
        "enterprise_status": data["status"],
        "color": color
    }
        
def create_access_token(data: dict):

    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")
        role = payload.get("role")

        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        conn = get_conn()
        cursor = conn.cursor()

        try:
            cursor.execute(
                db_sql("""
                    SELECT
                        id,
                        username,
                        role,
                        tenant_id,
                        status,
                        is_active,
                        session_version
                    FROM users
                    WHERE username = ?
                    LIMIT 1
                """),
                (username,)
            )

            db_user = cursor.fetchone()

        finally:
            conn.close()

        if db_user:
            db_user = dict(db_user)

            status = str(
                db_user.get("status") or "active"
            ).lower()

            if status in ("blocked", "suspended") or not db_user.get("is_active", 1):
                raise HTTPException(
                    status_code=403,
                    detail="User account is suspended or blocked."
                )

            token_version = int(
                payload.get("session_version", 0)
            )

            db_version = int(
                db_user.get("session_version") or 0
            )

            if token_version != db_version:
                raise HTTPException(
                    status_code=401,
                    detail="Session has been revoked. Please sign in again."
                )

            role = db_user.get("role") or role

            return {
                "id": db_user.get("id"),
                "username": db_user.get("username"),
                "role": role,
                "tenant_id": db_user.get("tenant_id")
            }

        return {
            "id": payload.get("user_id"),
            "username": username,
            "role": role,
            "tenant_id": payload.get("tenant_id", "demo")
        }

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


def verify_token(token: str):

    if not token:
        return None

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload

    except JWTError:
        return None
def background_siem_processor():

    while True:

        if len(EVENT_STREAM["raw_events"]) > 0:

            event = EVENT_STREAM["raw_events"].pop(0)

            # simple enrichment
            event["processed"] = True
            event["processed_at"] = datetime.utcnow().isoformat()

            EVENT_STREAM["processed_events"].append(event)

        time.sleep(1)
def soc_reasoning_engine(category: str, score: float, corr_id: str):

    """
    Autonomous reasoning layer
    """

    base_risk = score * SOC_REASONING_STATE["risk_bias"]

    # Learned behavior increases confidence
    if category in SOC_MEMORY["learned_behaviors"]:
        base_risk *= 1.15

    # Recent incident pressure
    recent_pressure = len(SOC_MEMORY["recent_incidents"]) / 50
    base_risk += recent_pressure * 10

    # --------- NEW AUTONOMOUS BRAIN ----------

    next_stage_map = {
        "Phishing": "Credential Access",
        "Fraud": "Execution",
        "Malware": "Persistence",
        "Harassment": "Impact",
        "Safe": "None"
    }

    predicted_stage = next_stage_map.get(category, "Unknown")

    confidence = min(
        100,
        int(base_risk + len(SOC_MEMORY["recent_incidents"]))
    )

    decision = soc_decision_engine(category, base_risk, corr_id)

    reasoning = {
        "current_category": category,
        "current_score": round(base_risk, 2),
        "predicted_next_stage": predicted_stage,
        "confidence": confidence,
        "recommended_action": decision,
        "timestamp": now_ts()
    }

    SOC_REASONING_STATE["last_decisions"].append(reasoning)

    # Keep only last 100 decisions
    if len(SOC_REASONING_STATE["last_decisions"]) > 100:
        SOC_REASONING_STATE["last_decisions"] = (
            SOC_REASONING_STATE["last_decisions"][-100:]
        )

    return reasoning
def auto_tune_risk_model():

    """
    Adjust SOC sensitivity based on system behavior
    """

    recent = SOC_MEMORY["recent_incidents"]

    if len(recent) < 10:
        return

    avg_recent_risk = sum(x["score"] for x in recent[-10:]) / 10

    # ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â´ too many threats ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ increase sensitivity
    if avg_recent_risk > 80:
        SOC_REASONING_STATE["risk_bias"] += 0.05

    # ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â¢ too safe ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ reduce sensitivity
    elif avg_recent_risk < 30:
        SOC_REASONING_STATE["risk_bias"] -= 0.03

    # clamp
    SOC_REASONING_STATE["risk_bias"] = max(0.5, min(2.0, SOC_REASONING_STATE["risk_bias"]))
def autonomous_event_correlator(category: str, score: float, corr_id: str):

    global ATTACK_GRAPH

    """
    Automatically links related threats without rules
    """

    ensure_timeline(corr_id)
    if corr_id not in ATTACK_CORRELATION:
        ATTACK_CORRELATION[corr_id] = []

    for other_id, node in ATTACK_GRAPH["nodes"].items():

        if other_id == corr_id:
            continue

        similarity = 0

        if node["category"] == category:
            similarity += 0.6

        score_diff = abs(node.get("max_score", node.get("score", 0)) - score)
        if score_diff < 15:
            similarity += 0.4

        if similarity >= 0.7:
            ATTACK_CORRELATION[corr_id].append({
    "id": other_id,
    "category": node["category"],
    "score": node.get("max_score", node.get("score", 0)),
    "stage": node.get("stage", "Unknown")
})
            add_graph_edge(corr_id, other_id, category)

            ATTACK_TIMELINE[corr_id].append({
                "type": "auto_correlation",
                "linked_to": other_id,
                "score": similarity,
                "timestamp": now_ts()
            })
def soc_autonomous_orchestrator(category: str, score: float, corr_id: str):
    global ATTACK_GRAPH

    # 1. Memory learning
    update_soc_memory(category, score, corr_id)

    # 2. Risk tuning
    auto_tune_risk_model()

    # 3. Event correlation
    autonomous_event_correlator(category, score, corr_id)

    # 4. Reasoning engine
    decision = soc_reasoning_engine(category, score, corr_id)

    # 5. GRAPH MEMORY (single system)
    if category == "Phishing":
        stage = "Initial Access"

    elif category == "Malware":
        stage = "Execution"

    elif category == "Fraud":
        stage = "Credential Access"

    elif category == "Harassment":
        stage = "Impact"

    else:
        stage = "Discovery"

    if category == "Phishing":
        mitre = "T1566 - Phishing"

    elif category == "Malware":
        mitre = "T1204 - User Execution"

    elif category == "Fraud":
        mitre = "T1056 - Input Capture"

    elif category == "Harassment":
        mitre = "T1562 - Impair Defenses"

    else:
        mitre = "T1595 - Active Scanning"

    add_graph_node(
        corr_id,
        category,
        score,
        stage,
        mitre
    )
    if category == "Phishing":
        add_graph_edge("Email", "Phishing", category)
        add_graph_edge("Phishing", "Credential Theft", category)

    elif category == "Malware":
        add_graph_edge("Malware", "Endpoint Compromise")

    elif category == "Fraud":
        add_graph_edge("Message", "Fraud")

    elif category == "Harassment":
        add_graph_edge("User Report", "Harassment")
    print("ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ GRAPH NODE ADDED")
    print(ATTACK_GRAPH)

    build_attack_clusters()

    for existing_id, node in ATTACK_GRAPH["nodes"].items():

        if existing_id == corr_id:
            continue

        if node.get("stage") == stage:
            add_graph_edge(
                existing_id,
                corr_id,
                f"{node['stage']} ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ {stage}"
            )

        elif abs(node.get("max_score", node.get("score", 0)) - score) <= 15:
            add_graph_edge(
                existing_id,
                corr_id,
                "related_attack"
            )

    return decision
def build_attack_clusters():

    ATTACK_GRAPH["clusters"] = {}

    for node_id, node in ATTACK_GRAPH["nodes"].items():

        category = node["category"]

        if category not in ATTACK_GRAPH["clusters"]:
            ATTACK_GRAPH["clusters"][category] = []

        ATTACK_GRAPH["clusters"][category].append(node_id)

    return ATTACK_GRAPH["clusters"]
# =========================
# ANALYZE ENDPOINT
# =========================

class AnalyzeRequest(BaseModel):
    text: str


class ThreatHuntRequest(BaseModel):
    category: str | None = None
    severity: str | None = None
    username: str | None = None
    status: str | None = None
    min_score: int | None = None
    max_score: int | None = None
    keyword: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


FAKE_USERS = {
    "admin": {
        "password": hash_password(os.getenv("ADMIN_PASSWORD")),
        "role": "admin"
    },
    "analyst": {
        "password": hash_password(os.getenv("ANALYST_PASSWORD")),
        "role": "analyst"
    },
    "viewer": {
        "password": hash_password(os.getenv("VIEWER_PASSWORD")),
        "role": "viewer"
    }
}

from fastapi import Header


@app.post("/login")
def login(request: LoginRequest):

    user = FAKE_USERS.get(request.username)

    print("LOGIN USER:", request.username, flush=True)
    print("LOGIN PASSWORD:", repr(request.password), flush=True)
    print("USER FOUND:", user is not None, flush=True)

    if not user:
        return {
        "success": False,
        "message": "Invalid username"
    }

    print(
    "ENDPOINT VERIFY:",
    verify_password(request.password, user["password"]),
    flush=True
)

    verified = verify_password(
        request.password,
        user["password"]
    )

    print("VERIFY RESULT:", verified, flush=True)

    if not verified:
        return {
            "success": False,
            "message": "Invalid password"
        }

    token = create_access_token(
        {
            "sub": request.username,
            "role": user["role"]
        }
    )

    return {
    "success": True,
    "message": "Login successful",
    "token": token,
    "role": user["role"]
}
def block_source(incident_id):
    print(f"[SOC] Blocking source for incident {incident_id}")


def isolate_endpoint(incident_id):
    print(f"[SOC] Isolating endpoint for incident {incident_id}")


def quarantine_message(incident_id):
    print(f"[SOC] Quarantining malicious message for incident {incident_id}")


def notify_admin(incident_id):
    print(f"[SOC] Notifying administrator for incident {incident_id}")


def flag_for_review(incident_id):
    print(f"[SOC] Flagging incident {incident_id} for analyst review")
SOC_PLAYBOOKS = {

    "Phishing": [
        "QUARANTINE_MESSAGE",
        "BLOCK_SOURCE",
        "RESET_CREDENTIALS",
        "NOTIFY_ADMIN"
    ],

    "Malware": [
        "ISOLATE_ENDPOINT",
        "BLOCK_SOURCE",
        "RUN_AV_SCAN",
        "ESCALATE_SOC"
    ],

    "Ransomware": [
        "ISOLATE_ENDPOINT",
        "BLOCK_SOURCE",
        "DISABLE_NETWORK",
        "ESCALATE_SOC"
    ],

    "Credential Theft": [
        "RESET_CREDENTIALS",
        "FORCE_MFA",
        "NOTIFY_ADMIN"
    ],

    "Fraud": [
        "BLOCK_SOURCE",
        "FLAG_FOR_REVIEW"
    ]
}
def update_incident_commander(
    incident_id,
    category,
    score,
    status
):

    ACTIVE_INCIDENTS[incident_id] = {
        "incident_id": incident_id,
        "category": category,
        "score": score,
        "status": status,
        "timestamp": now_ts()
    }

    return ACTIVE_INCIDENTS
def close_incident(incident_id):

    if incident_id in ACTIVE_INCIDENTS:
        del ACTIVE_INCIDENTS[incident_id]

    return {
        "success": True
    }
def autonomous_soc_response(incident_id, category, score):

    actions = SOC_PLAYBOOKS.get(category, [])

    if not actions:

        if score >= 90:
            actions = [
                "BLOCK_SOURCE",
                "ISOLATE_ENDPOINT",
                "ESCALATE_SOC"
            ]

        elif score >= 80:
            actions = [
                "QUARANTINE_MESSAGE",
                "NOTIFY_ADMIN"
            ]

        elif score >= 60:
            actions = [
                "FLAG_FOR_REVIEW"
            ]

        else:
            actions = [
                "LOG_ONLY"
            ]

    for action in actions:

        if action == "BLOCK_SOURCE":
            block_source(incident_id)

        elif action == "ISOLATE_ENDPOINT":
            isolate_endpoint(incident_id)

        elif action == "QUARANTINE_MESSAGE":
            quarantine_message(incident_id)

        elif action == "NOTIFY_ADMIN":
            notify_admin(incident_id)

        elif action == "FLAG_FOR_REVIEW":
            flag_for_review(incident_id)

        elif action == "LOG_ONLY":
            print(f"[SOC] Logged incident {incident_id}")

    return actions
    class LoginRequest(BaseModel):
        username: str
        password: str

@app.post("/analyze")
async def analyze(payload: AnalyzeRequest):
    global LAST_CORRELATION_ID

    print("ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â¥ ANALYZE ENDPOINT HIT")

    user = {
        "username": "developer",
        "role": "admin"
    }
    category, score, stage, mitre, confidence, matches = classify_threat(payload.text)

    event = {
    "category": category,
    "score": score,
    "stage": stage,
    "mitre": mitre,
    "confidence": confidence,
    "matches": matches,
    "username": getattr(payload, "username", ""),
    "hostname": getattr(payload, "hostname", ""),
    "source_ip": getattr(payload, "source_ip", "")
}

    campaign = engine_detect_campaign(event)
    add_event(event)

    print("CALLING add_replay_event()")
    add_replay_event(event)
    print("RETURNED FROM add_replay_event()")

    print("CLASSIFIER OUTPUT:", category, score)
    print("ANALYZE COMPLETE")
    iocs = extract_iocs(payload.text)

    if iocs:
        update_ioc_database(iocs)

    print("CATEGORY =", category)
    print("SCORE =", score)

    iocs = extract_iocs(payload.text)
    intel_results = enrich_iocs(iocs)
    update_ioc_database(iocs)

    print("IOCS FOUND")
    print(iocs)
    print("PASSED IOC STAGE")

    if not check_permission(user["role"], "analyze"):
        print("ANALYZE RETURNING:")
        print(result)
        return {
            "success": False,
            "error": "INSUFFICIENT_PERMISSIONS"
        }

    status = calculate_status(score)
    anomaly_flag = predict_threat_anomaly(score)

    scan_id = create_scan(
        payload.text,
        category,
        score,
        status,
        user["username"],
        tenant_id="demo"
    )

    print("SCAN SAVED =", scan_id)

    corr_id = None
    incident_id = None
    auto_escalation = None
    mitre = None
    decision = None
    intel = None

    brain = None
    prediction = None
    kill_chain = None
    prediction_engine = None

    # ---------------------------------------
    # Threat Processing
    # ---------------------------------------
    if category != "Safe":

        print("===== THREAT DETECTED =====")
        print("CATEGORY =", category)
        print("SCORE =", score)

    intel = upsert_threat_intelligence(
        indicator=category,
        category=category,
        score=score
    )

    print("INTEL =", intel)

    corr_id = generate_correlation_key(
        category,
        payload.text
    )

    # Determine ATT&CK stage
    

    mitre = mitre_lookup(category)

    print("CORR_ID =", corr_id)

    create_alert(
        payload.text,
        status,
        "demo"
    )

    if corr_id not in ATTACK_TIMELINE:
        ATTACK_TIMELINE[corr_id] = []
    mitre_info = mitre_lookup(category)

    if isinstance(mitre_info, dict):
        stage = mitre_info.get("tactic", stage)
        mitre = f"{mitre_info.get('id', 'TA0000')} - {mitre_info.get('technique', 'Unknown')}"
    else:
        mitre = str(mitre_info)

    incident_id = create_incident(
        scan_id=scan_id,
        message=payload.text,
        category=category,
        threat_type=category,
        risk_score=score,
        severity=status,
        stage=stage,
        mitre=mitre,
        tenant_id=getattr(payload, "tenant_id", "demo"),
        threat_intel=json.dumps(intel, default=str),
        correlation_id=corr_id
    )

    print("INCIDENT ID =", incident_id)
# -------------------------
# Update attack graph FIRST
# -------------------------
    ATTACK_GRAPH["nodes"][str(incident_id)] = {
    "id": str(incident_id),
    "category": category,
    "max_score": score,
    "score": score,
    "stage": stage,
    "mitre": mitre,
    "count": 1
}

    ids = list(ATTACK_GRAPH["nodes"].keys())

    if len(ids) >= 2:
        add_graph_edge(
        ids[-2],
        ids[-1],
        category
    )

    graph = add_graph_node(
    corr_id,
    category,
    score,
    stage,
    mitre
)
# # Create attack chain edge
    if LAST_CORRELATION_ID and LAST_CORRELATION_ID != corr_id:
        add_graph_edge(
            LAST_CORRELATION_ID,
            corr_id,
            category
        )

    print("GRAPH AFTER INSERT")
    print(ATTACK_GRAPH)

    LAST_CORRELATION_ID = corr_id


    decision = soc_autonomous_orchestrator(
        category,
        score,
        corr_id
    )

    kill_chain = analyze_kill_chain(category)


    brain = {
        "risk_level": status,
        "category": category,
        "score": score,
        "prediction": predict_next_attack(),
        "campaign": analyze_campaign(
            ATTACK_CORRELATION.get(corr_id, [])
        ),
        "kill_chain": kill_chain,
        "reasoning": decision,
        "predicted_next_stage": decision.get("predicted_next_stage"),
        "confidence": decision.get("confidence"),
        "recommended_action": decision.get("recommended_action")
    }


    await push_event(
        "alert_event",
        {
            "message": payload.text,
            "category": category,
            "score": score,
            "status": status
        }
    )


    await push_event(
    "auto_response_event",
    {
        "correlation_id": corr_id,
        "category": category,
        "score": score,
        "decision": decision
    }
)


    await push_event(
    "ai_decision_event",
    {
        "correlation_id": corr_id,
        "decision": decision
    }
)


    # ---------------------------------------
    # NEW THREAT BROADCAST
    # ---------------------------------------

    if corr_id:

        import random

        locations = [
            {"country": "Kenya", "lat": -1.286389, "lng": 36.817223},
            {"country": "USA", "lat": 38.89511, "lng": -77.03637},
            {"country": "China", "lat": 39.9042, "lng": 116.4074},
            {"country": "Russia", "lat": 55.7558, "lng": 37.6176},
            {"country": "Germany", "lat": 52.52, "lng": 13.405},
            {"country": "Brazil", "lat": -15.793889, "lng": -47.882778},
            {"country": "India", "lat": 28.6139, "lng": 77.2090},
            {"country": "Japan", "lat": 35.6895, "lng": 139.6917},
            {"country": "South Africa", "lat": -25.7461, "lng": 28.1881}
        ]

        location = random.choice(locations)

        await manager.broadcast({
            "type": "new_threat",
            "node": {
                "id": corr_id,
                "category": category,
                "score": score,
                "country": location["country"],
                "lat": location["lat"],
                "lng": location["lng"]
            },
            "mitre": mitre
        })

    # ---------------------------------------
    # DEBUG
    # ---------------------------------------
    print("===== BEFORE BROADCAST =====")
    print("ATTACK_GRAPH =", ATTACK_GRAPH)
    print("NODES =", ATTACK_GRAPH["nodes"])
    print("EDGES =", ATTACK_GRAPH["edges"])
    print("============================")

    # ---------------------------------------
    # THREAT INTELLIGENCE + GRAPH
    # ---------------------------------------
    if intel is not None:

        await manager.broadcast({
            "type": "threat_intelligence",
            "data": intel
        })
    print("GRAPH BEFORE BROADCAST =", ATTACK_GRAPH)

    await manager.broadcast({
        "type": "attack_graph",
        "nodes": [
            {
                "id": node_id,
                "category": node["category"],
                "score": node.get("max_score", node.get("score", 0)),
                "count": node.get("count", 1)
            }
            for node_id, node in ATTACK_GRAPH["nodes"].items()
            if node["category"] != "Safe"
        ],
        "links": ATTACK_GRAPH["edges"]
    })
    if len(ATTACK_GRAPH["nodes"]) > 1:
        add_graph_edge(
        list(ATTACK_GRAPH["nodes"].keys())[-2],
        corr_id,
        "attack_chain"
    )
    await manager.broadcast({
    "type": "attack_graph_live",
    "graph": {
        "nodes": list(ATTACK_GRAPH["nodes"].values()),
        "links": ATTACK_GRAPH["edges"]
    }
})
    await manager.broadcast({
    "type": "dashboard_update",
    "data": {
        "category": category,
        "score": score,
        "status": status,
        "correlation_id": corr_id
    }
})
    await manager.broadcast({
    "type": "response_timeline",
    "data": decision
})
    update_incident_commander(
    incident_id,
    category,
    score,
    status
)
    autonomous_soc_response(
    incident_id,
    category,
    score
)
    # ---------------------------------------
    # RESPONSE
    # ---------------------------------------
    return {
    "success": True,
    "data": {
        "category": category,
        "score": score,
        "status": status,
        "anomaly": anomaly_flag,
        "mitre": mitre,

        "threat_intelligence": intel,
        "correlation_id": corr_id,
        "iocs": iocs,

        "soc_brain": brain,
        "prediction": prediction,

        "campaign": campaign["campaign"],
        "campaign_id": campaign["id"],
        "campaign_status": campaign["status"],
        "campaign_severity": campaign["severity"],
        "campaign_confidence": campaign["confidence"],
        "campaign_users": campaign["users"],
        "campaign_hosts": campaign["hosts"],
        "campaign_ips": campaign["ips"],
        "campaign_mitre": campaign["mitre"],
        "campaign_kill_chain": campaign["kill_chain"],
        "campaign_events": campaign["events"],

        "kill_chain": kill_chain,
        "prediction_engine": prediction_engine
    }
}
# =========================
# INCIDENTS
# =========================

@app.get("/incidents")
def incidents(tenant_id: str = "demo"):
    return get_incidents(tenant_id)
@app.put("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: int):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE incidents
        SET status='RESOLVED'
        WHERE id=?
    """, (incident_id,))

    conn.commit()
    conn.close()

    return {"success": True}
@app.put("/incidents/{incident_id}/investigate")
def investigate_incident(incident_id: int):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE incidents
        SET status='INVESTIGATING'
        WHERE id=?
    """, (incident_id,))

    conn.commit()
    conn.close()

    return {"success": True}
class AssignRequest(BaseModel):
    assigned_to: str


@app.put("/incidents/{incident_id}/assign")
def assign_incident(incident_id: int, request: AssignRequest):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE incidents
        SET assigned_to = ?
        WHERE id = ?
    """, (request.assigned_to, incident_id))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "assigned_to": request.assigned_to
    }


@app.get("/incidents/open")
def open_incidents():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM incidents WHERE status='OPEN'")
    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]

# =========================
# ALERTS (IN MEMORY)
# =========================

@app.get("/alerts")
def alerts(limit: int = 20):
    return {
        "count": len(ALERT_LOG),
        "data": ALERT_LOG[-limit:]
    }

# =========================
# SOC SUMMARY
# =========================

@app.get("/soc-summary")
def soc_summary():

    incidents = get_incidents()

    # only recent SOC activity
    incidents = incidents[-50:]

    nodes = []

    for i in incidents:

        nodes.append({
            "id": i.get("id"),
            "category": i.get("category", "Unknown"),
            "score": (
                i.get("score")
                or i.get("risk_score")
                or 0
            ),
            "stage": i.get("stage", "Unknown"),
            "mitre": i.get("mitre", "Unknown")
        })


    active = [
        n for n in nodes
        if n["category"] != "Safe"
    ]


    critical = [
        n for n in active
        if n["score"] >= 80
    ]


    risk_penalty = (
        len(critical) * 2
        + len(active) * 0.5
    )


    security_score = max(
        0,
        int(100 - risk_penalty)
    )


    return {
        "status": "ok",
        "total_nodes": len(nodes),
        "active_threats": len(active),
        "critical": len(critical),
        "critical_threats": len(critical),
        "security_score": security_score,
        "graph": {
            "nodes": nodes,
            "edges": ATTACK_GRAPH.get("edges", [])
        }
    }
@app.get("/executive-summary")
def executive_summary():

    nodes = ATTACK_GRAPH["nodes"]

    active = [
        node for node in nodes.values()
        if node.get("category") != "Safe"
    ]

    # fallback to incidents database
    if len(active) == 0:

        incidents = get_incidents()

        active = [
    {
        "category": i.get("category", "Unknown"),
        "max_score": (
            i.get("score")
            or i.get("risk_score")
            or i.get("severity_score")
            or 0
        )
    }
    for i in incidents
]

    total_threats = len(active)

    highest_score = max(
        [n.get("max_score", 0) for n in active],
        default=0
    )

    critical = len([
        n for n in active
        if n.get("max_score", 0) >= 85
    ])

    if highest_score >= 90:
        risk_level = "CRITICAL"

    elif highest_score >= 75:
        risk_level = "HIGH"

    elif highest_score >= 50:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_level": risk_level,
        "risk_score": highest_score,
        "active_threats": total_threats,
        "critical_threats": critical,
        "recommendation":
            "Immediate investigation required"
            if risk_level in ["HIGH", "CRITICAL"]
            else "Security posture stable"
    }
# =========================
# WEBSOCKET
# =========================

@app.websocket("/ws/alerts")
async def alerts_stream(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            # simulate SOC events (replace later with real logs)
            event = {
                "id": random.randint(1000, 9999),
                "level": random.choice(["Low", "Medium", "High Risk"]),
                "message": random.choice([
                    "Suspicious login detected",
                    "Port scan activity detected",
                    "Malware signature matched",
                    "Unusual API traffic spike"
                ]),
                "created_at": datetime.utcnow().isoformat()
            }

            await websocket.send_text(json.dumps(event))
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        active_connections.remove(websocket)
# =========================
# LIVE LOOP (REAL-TIME SOC STREAM)
# =========================

async def soc_live_loop():

    while True:

        try:
            payload = build_executive_payload()

            await manager.broadcast(payload)

            await push_event(
                "threat_intelligence",
                {
                    "velocity": get_threat_velocity(),
                    "anomaly": get_threat_anomaly_score(),
                    "soc_core": get_soc_intelligence_core()
                }
            )

        except Exception as e:
            print("SOC LOOP ERROR:", e)

        await asyncio.sleep(5)
# =========================
# STARTUP
# =========================

@app.on_event("startup")
async def startup():
    Thread(target=background_siem_processor, daemon=True).start()
    init_db()
    init_event_correlation()
    add_threat_intel_column()
    train_threat_model()

    # ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â¥ ADD THIS TEST NODE
    await manager.broadcast({
        "type": "new_threat",
        "node": {
            "id": "seed-node-1",
            "category": "phishing",
            "score": 88
        }
    })

    asyncio.create_task(soc_live_loop())
    print("ÃƒÂ°Ã…Â¸Ã…Â¡Ã¢â€šÂ¬ SOC SYSTEM STARTED")
# =========================
# DASHBOARD UI (MINIMAL)
# =========================

@app.get("/ui", response_class=HTMLResponse)
def ui():

    return """
    <html>
    <head>
        <title>Enterprise SOC SIEM</title>
    </head>

    <body style="background:#0b1220;color:white;font-family:Arial;">

        <h1>ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â¥ ENTERPRISE SOC SIEM</h1>

        <pre id="feed">Connecting...</pre>

        <script>
            const wsProtocol =
    window.location.protocol === "https:" ? "wss://" : "ws://";

    const ws = new WebSocket(
    wsProtocol + window.location.host + "/ws/alerts"
);

            ws.onmessage = function(event) {
                document.getElementById("feed").innerText =
                JSON.stringify(JSON.parse(event.data), null, 2);
            };
        </script>

    </body>
    </html>
    """
@app.get("/debug-executive")
def debug_executive():
    return build_executive_payload()
@app.get("/fix-incidents")
def fix_incidents():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE incidents
        SET status='OPEN'
        WHERE status IS NULL
    """)

    conn.commit()

    fixed = cur.rowcount

    conn.close()

    return {"fixed": fixed}
@app.get("/test-incident-update")
def test_incident_update():

    return update_incident_status(
        1,
        "RESOLVED",
        "Manual test"
    )
@app.get("/soc-health")
def soc_health():
    data = soc_metrics()

    return {
        "soc_score": data["soc_health"],
        "status": data["status"]
    }
@app.get("/threat-intelligence")
def threat_intelligence():

    return {
        "trends": get_threat_trends(),
        "velocity": get_threat_velocity(),
        "anomaly": get_threat_anomaly_score(),
        "soc_core": get_soc_intelligence_core()
    }
@app.post("/intel/enrich")
async def enrich_intelligence(payload: dict):

    iocs = payload.get("iocs", [])

    results = analyze_iocs(iocs)

    for item in results:
        save_threat_ioc(item)

    return {
    "count": len(results),
    "results": results
}
@app.get("/events/{event_type}")
def get_events(event_type: str):

    return {
        "event_type": event_type,
        "count": len(EVENT_STREAM.get(event_type, [])),
        "events": EVENT_STREAM.get(event_type, [])
    }
def detect_attack_burst():
    alerts = EVENT_STREAM.get("alert_event", [])[-20:]

    if len(alerts) < 10:
        return {"burst": False}

    timestamps = [
        datetime.fromisoformat(e["timestamp"])
        for e in alerts
    ]

    duration = (timestamps[-1] - timestamps[0]).seconds

    if duration < 30:
        return {
            "burst": True,
            "severity": "HIGH"
        }

    return {"burst": False}
@app.get("/attack-timeline/{corr_id}")
def get_attack_timeline(corr_id: str):

    return {
        "correlation_id": corr_id,
        "events": ATTACK_TIMELINE.get(corr_id, [])
    }
@app.get("/autonomy-test")
def autonomy_test():

    return {
        "auto_response_sample": auto_response_engine("Phishing", 92, "test123"),
        "status": "AUTONOMY ENGINE ACTIVE"
    }
from typing import List, Optional
class GraphNode(BaseModel):
    id: str
    category: Optional[str] = "Unknown"
    score: Optional[float] = 0
    stage: Optional[str] = ""
    mitre: Optional[str] = ""


class GraphLink(BaseModel):
    source: str
    target: str


class Alert(BaseModel):
    id: int | str
    message: str
    severity: Optional[str] = ""
class GraphNode(BaseModel):
    id: str
    category: str | None = None
    score: float | None = 0
    stage: str | None = ""
    mitre: str | None = ""


class GraphLink(BaseModel):
    source: str
    target: str


class Alert(BaseModel):
    id: int | None = None
    message: str
    severity: str | int | None = None


class SOCAIRequest(BaseModel):
    nodes: List[GraphNode]
    links: List[GraphLink]
    alerts: List[Alert]

def analyze_campaign(nodes):

    if not nodes:
        return {
            "name": "Unknown",
            "confidence": 0,
            "description": "No campaign detected.",
            "categories": [],
            "stages": [],
            "incident_count": 0
        }

    # remove invalid nodes
    nodes = [n for n in nodes if isinstance(n, dict)]

    highest = max(nodes, key=lambda x: x.get("score", 0))

    categories = Counter(
        n.get("category", "Unknown")
        for n in nodes
    )

    stages = Counter(
        n.get("stage", "Unknown")
        for n in nodes
    )

    return {
        "name": f"{highest.get('category')} Campaign",
        "confidence": highest.get("score", 0),
        "description": f"{len(nodes)} correlated incidents detected.",
        "categories": dict(categories),
        "stages": dict(stages),
        "incident_count": len(nodes)
    }
@app.post("/soc-ai")
async def soc_ai(payload: dict):

    nodes = payload.get("nodes", [])
    alerts = payload.get("alerts", [])
    text = payload.get("text", "")

    # Allow direct threat analysis
    if text:

        category, score, stage, mitre, confidence, matches = classify_threat(text)

        status = calculate_status(score)

        corr_id = str(uuid4())

        event = {
            "category": category,
            "score": score,
            "stage": stage,
            "mitre": mitre,
            "confidence": confidence,
            "matches": matches,
            "username": payload.get("username", ""),
            "hostname": payload.get("hostname", ""),
            "source_ip": payload.get("source_ip", "")
        }

        campaign = engine_detect_campaign(event)

        add_event(event)
        add_replay_event(event)

        create_alert(
            text,
            status,
            "demo"
        )

        incident_id = create_incident(
            scan_id=None,
            message=text,
            category=category,
            threat_type=category,
            risk_score=score,
            severity=status,
            stage=stage,
            mitre=mitre,
            tenant_id="demo",
            threat_intel="{}",
            correlation_id=corr_id
        )

        add_graph_node(
            corr_id,
            category,
            score,
            stage,
            mitre
        )

        return {
            "success": True,
            "incident_id": incident_id,
            "category": category,
            "score": score,
            "stage": stage,
            "mitre": mitre,
            "confidence": confidence,
            "matches": matches,
            "campaign": campaign,
            "status": status,
            "graph": ATTACK_GRAPH
        }

    if not nodes:
        return {
            "summary": "No incidents available.",
            "highest_risk": {},
            "root_cause": {},
            "mitre_timeline": [],
            "attack_story": "",
            "recommendation": "No action required."
        }
    highest = max(nodes, key=lambda n: n.get("score", 0))
    print("HIGHEST NODE =", highest)
    print("ALL NODES =", nodes)

    mitre_timeline = []

    for n in nodes:
        mitre_timeline.append({
            "id": n.get("id", "Unknown"),
            "stage": n.get("stage", "Unknown"),
            "technique": n.get("mitre", "Unknown"),
            "score": n.get("score", 0)
        })

    # Remove invalid nodes first
    valid_nodes = [
    n for n in nodes
    if n.get("id") is not None
    and "-" in str(n.get("id"))
]

    if valid_nodes:
        valid_nodes = [
    n for n in nodes
    if isinstance(n, dict)
    and n.get("id")
    and "-" in str(n.get("id"))
]

    if valid_nodes:
        root = min(
        valid_nodes,
        key=lambda x: int(str(x["id"]).split("-")[1])
    )
    else:
        root = highest
      
    summary = (
        f"Detected {len(nodes)} incidents. "
        f"Highest risk is {highest.get('category', 'Unknown')} "
        f"with score {highest.get('score', 0)}."
    )

    recommendation = (
        "Immediately isolate affected assets, "
        "block malicious indicators, "
        "review user activity, "
        "and continue monitoring."
    )

    attack_story = (
        f"The attack began with {root.get('category', 'Unknown')} "
        f"({root.get('id', 'Unknown')}). "
        f"It progressed through {len(nodes)} correlated incidents. "
        f"The highest-risk event was {highest.get('category', 'Unknown')} "
        f"with a risk score of {highest.get('score', 0)}. "
        f"The attack reached the {highest.get('stage', 'Unknown')} stage "
        f"mapped to MITRE technique {highest.get('mitre', 'Unknown')}. "
        f"Immediate containment is recommended."
    )
    response = generate_soc_response(highest)

    await manager.broadcast({
    "type": "campaign_update",
    "campaign": highest.get("campaign", "Unknown"),
    "summary": summary,
    "highest_risk": highest
})
    campaign = analyze_campaign(nodes)
    ai_confidence = round(
    (highest.get("score", 0) + campaign["confidence"]) / 2,
    1
)
    print("CAMPAIGN =", campaign)

    return {
    "summary": summary,
    "attack_story": attack_story,
    "highest_risk": highest,
    "root_cause": root,
    "mitre_timeline": mitre_timeline,
    "recommendation": recommendation,"campaign": campaign["name"],
    "campaign_confidence": campaign["confidence"],
    "campaign_description": campaign["description"],
    "campaign_categories": campaign["categories"],
    "campaign_stages": campaign["stages"],
    "incident_count": campaign["incident_count"],
    "soc_level": response["level"],
    "soc_actions": response["actions"],
    "executive_summary": response["executive_summary"],
    "escalation": response["escalation"],
    "ai_confidence": ai_confidence,
    "response": response,
}
def generate_soc_response(highest):

    score = float(highest.get("score", 0))
    category = highest.get("category", "Unknown")
    stage = highest.get("stage", "Unknown")
    mitre = highest.get("mitre", "Unknown")

    if score >= 90:
        level = "CRITICAL"
        escalation = True

    elif score >= 75:
        level = "HIGH"
        escalation = True

    elif score >= 50:
        level = "MEDIUM"
        escalation = False

    else:
        level = "LOW"
        escalation = False

    actions = []

    if category == "Phishing":
        actions = [
            "Block phishing domain",
            "Reset affected user passwords",
            "Revoke active sessions",
            "Search all mailboxes for similar emails",
            "Notify affected users"
        ]

    elif category == "Malware":
        actions = [
            "Isolate infected endpoint",
            "Run EDR scan",
            "Collect malware sample",
            "Block IOC hash",
            "Check lateral movement"
        ]

    elif category == "Brute Force":
        actions = [
            "Lock compromised account",
            "Block attacker IP",
            "Enable MFA",
            "Review authentication logs",
            "Reset credentials"
        ]

    elif category == "Ransomware":
        actions = [
            "Disconnect endpoint",
            "Disable SMB shares",
            "Start forensic imaging",
            "Restore from backup",
            "Notify Incident Response Team"
        ]

    else:
        actions = [
            "Monitor activity",
            "Collect evidence",
            "Review logs"
        ]

    return {
        "level": level,
        "category": category,
        "risk_score": score,
        "stage": stage,
        "mitre": mitre,
        "escalation": escalation,
        "actions": actions,
        "executive_summary": (
            f"{category} activity detected with a risk score of {score}. "
            f"The attack is currently in the {stage} phase and maps to {mitre}. "
            f"Severity has been classified as {level}."
        )
    }
def find_similar_incidents(incident, incidents):

    return [
        i for i in incidents
        if (
            i["id"] != incident["id"]
            and i["category"] == incident["category"]
        )
    ]
def explain_incident(incident):

    return {
        "incident": incident["id"],
        "category": incident["category"],
        "severity": incident["severity"],
        "risk_score": incident["risk_score"],
        "explanation": (
            f"This {incident['category']} incident has a risk score "
            f"of {incident['risk_score']}. "
            f"It is classified as {incident['severity']}."
        ),
        "recommendations": recommend_actions(incident)
    }
def recommend_actions(incident):

    score = incident.get("risk_score", 0)

    category = incident.get("category", "")

    actions = []

    if category == "Phishing":
        actions.extend([
            "Block sender domain",
            "Reset affected user password",
            "Enable MFA",
            "Search mailbox for similar emails"
        ])

    elif category == "Malware":
        actions.extend([
            "Isolate infected endpoint",
            "Run antivirus scan",
            "Collect forensic evidence",
            "Restore from backup if required"
        ])

    elif category == "Brute Force":
        actions.extend([
            "Lock affected account",
            "Block source IP",
            "Enable MFA",
            "Review authentication logs"
        ])

    if score >= 80:
        actions.append("Escalate to SOC Manager")

    return actions
@app.post("/soc-chat")
async def soc_chat(payload: dict):

    query = payload.get("query", "").lower()

    incidents = get_incidents("demo")
    iocs = get_threat_intelligence()
    if "assign" in query:

        digits = "".join(c for c in query if c.isdigit())

        # ---------------------------------
    # Investigate incident
    # ---------------------------------
    if "investigate" in query and "incident" in query:
        # ---------------------------------
        # Explain / Why incident
        # ---------------------------------
        if (
            "why" in query
            or "explain" in query
            or "what happened" in query
            or "how" in query
        ):

            return {
                "action": "explanation",
                "incident_id": incident_id,
                "summary": (
                    f"Incident {incident_id} is a "
                    f"{incident.get('category')} threat "
                    f"with {incident.get('severity')} severity."
                ),
                "reason": (
                    "The message matched known threat patterns "
                    "and exceeded SOC risk thresholds."
                ),
                "risk_score": incident.get("risk_score"),
                "attack_stage": incident.get(
                    "stage",
                    "INITIAL ACCESS"
                ),
                "mitre": incident.get(
                    "mitre",
                    "T1566 - Phishing"
                ),
                "recommended_actions": recommend_actions(
                    incident
                )
            }

        digits = "".join(c for c in query if c.isdigit())

        if digits:
            incident_id = int(digits)

            incident = next(
                (
                    i for i in incidents
                    if i["id"] == incident_id
                ),
                None
            )

            if incident:

                return {
    "action": "investigate",
    "incident_id": incident_id,
    "category": incident.get("category"),
    "severity": incident.get("severity"),
    "status": incident.get("status"),
    "risk_score": incident.get("risk_score"),
    "message": incident.get("message"),

    "mitre": incident.get(
        "mitre",
        "T1566 - Phishing"
    ),

    "attack_stage": incident.get(
        "stage",
        "INITIAL ACCESS"
    ),

    "timeline": [
        "Detection event created",
        "Threat classification completed",
        "Risk score calculated",
        "SOC analyst investigation started"
    ],

    "similar_incidents": find_similar_incidents(
        incident,
        incidents
    )[:5],

    "recommendations": recommend_actions(incident),

    "explanation": explain_incident(incident)
}

        return {
            "answer": "Incident not found.",
            "results": []
        }

        words = query.split()

        analyst = words[-1].capitalize()

        return update_customer_incident(
            incident_id,
            CustomerIncidentUpdate(
                assigned_to=analyst,
                status="INVESTIGATING"
            )
        )

    # ---------------------------------
    # Incident by ID
    # ---------------------------------
    if (
    "incident" in query
    and "resolve" not in query
    and "assign" not in query
    and "why" not in query
    and "explain" not in query
    and "dangerous" not in query
    and "what happened" not in query
    and "how" not in query
):

        digits = "".join(c for c in query if c.isdigit())

        if digits:
            incident_id = int(digits)

            for incident in incidents:
                if incident["id"] == incident_id:

                    response = explain_incident(incident)

                    response["similar_incidents"] = find_similar_incidents(
                        incident,
                        incidents
                    )[:5]

                    response["recommendations"] = recommend_actions(incident)

                    return response

            return {
                "answer": "Incident not found.",
                "results": []
            }

    # ---------------------------------
    # Critical incidents
    # ---------------------------------
    if "critical" in query:

        results = [
            i for i in incidents
            if str(i.get("severity", "")).lower() == "critical"
        ]

        return {
            "answer": f"I found {len(results)} critical incidents.",
            "results": results
        }

    # ---------------------------------
    # Open incidents
    # ---------------------------------
    if "open" in query:

        results = [
            i for i in incidents
            if str(i.get("status", "")).upper() == "OPEN"
        ]

        return {
            "answer": f"I found {len(results)} open incidents.",
            "results": results
        }

    # ---------------------------------
    # Investigating incidents
    # ---------------------------------
    if "investigating" in query:

        results = [
            i for i in incidents
            if str(i.get("status", "")).upper() == "INVESTIGATING"
        ]

        return {
            "answer": f"I found {len(results)} investigating incidents.",
            "results": results
        }

    # ---------------------------------
    # Initial Access
    # ---------------------------------
    if "initial access" in query:

        results = [
            i for i in incidents
            if str(i.get("stage", "")).upper() == "INITIAL ACCESS"
        ]

        return {
            "answer": f"I found {len(results)} Initial Access incidents.",
            "results": results
        }

    # ---------------------------------
    # Execution
    # ---------------------------------
    if "execution" in query:

        results = [
            i for i in incidents
            if str(i.get("stage", "")).upper() == "EXECUTION"
        ]

        return {
            "answer": f"I found {len(results)} Execution incidents.",
            "results": results
        }

    # ---------------------------------
    # MITRE T1566
    # ---------------------------------
    if "t1566" in query:

        results = [
            i for i in incidents
            if "T1566" in str(i.get("mitre", ""))
        ]

        return {
            "answer": f"I found {len(results)} incidents using MITRE T1566.",
            "results": results
        }

    # ---------------------------------
# Default AI Copilot
# ---------------------------------
    result = soc_copilot(
    query,
    incidents,
    iocs
)

    if result.get("action") == "resolve":
        return update_incident_status(
        result["incident_id"],
        "RESOLVED"
    )

    if result.get("action") == "assign":
        return update_customer_incident(
    incident_id,
    CustomerIncidentUpdate(
        assigned_to=analyst,
        status="INVESTIGATING"
    )
)

    return result
@app.post("/soc-ai-stream")
async def soc_ai_stream(payload: dict):
    print("ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â¥ SOC-AI-STREAM ENDPOINT HIT")

    request = AnalyzeRequest(
        text=payload.get("text", "")
    )

    result = await analyze(request)

    ai = result["data"]

    risk = (
    ai.get("soc_brain", {}).get("risk_level", "UNKNOWN")
    if ai.get("soc_brain")
    else "UNKNOWN"
)

    if ai["category"] == "Safe":

        reply = f"""
Threat Assessment Complete

I analyzed your message and found no indicators of phishing, malware, credential theft, fraud, or social engineering.

Classification:
{ai["category"]}

Risk Score:
{ai["score"]}/100

Risk Level:
{risk}

Reasoning:
- No suspicious keywords detected.
- No malicious IOC indicators were extracted.
- No known attack patterns matched.
- No MITRE ATT&CK technique was triggered.

Recommended Action:
Continue normal operations.

Confidence:
98%
"""

    else:

        reply = f"""
Threat Assessment Complete

This communication appears malicious.

Classification:
{ai["category"]}

Risk Score:
{ai["score"]}/100

Risk Level:
{risk}

Why I believe this is malicious:
- Threat classification engine matched known attack patterns.
- Risk score exceeded the detection threshold.
- SOC Brain classified the event as {risk}.
"""

        if ai["mitre"]:
            reply += f"""

MITRE ATT&CK:
{ai["mitre"]}
"""

        if ai["iocs"]["urls"]:
            reply += f"""

Suspicious URLs:
{", ".join(ai["iocs"]["urls"])}
"""

        if ai["iocs"]["emails"]:
            reply += f"""

Suspicious Emails:
{", ".join(ai["iocs"]["emails"])}
"""

        if ai["iocs"]["ips"]:
            reply += f"""

Suspicious IPs:
{", ".join(ai["iocs"]["ips"])}
"""

        print("=== AI DEBUG ===")
        print(ai)
        print("================")

        reply += """

Recommended Actions:
- Isolate the affected endpoint.
- Block identified indicators.
- Review authentication logs.
- Notify the SOC team.

Confidence:
96%
"""

    return {
        "success": True,
        "reply": reply,
        "data": ai
    }


class IncidentUpdate(BaseModel):
    incident_id: int
    status: str
    notes: str = None


def ai_threat_hunter(results):

    if not results:
        return {
            "risk": "LOW",
            "summary": "No matching threats found.",
            "patterns": [],
            "recommendations": [
                "Continue monitoring."
            ]
        }

    categories = {}
    users = {}
    high = 0

    for r in results:

        categories[r["category"]] = categories.get(r["category"], 0) + 1

        users[r["username"]] = users.get(r["username"], 0) + 1

        if r["score"] >= 80:
            high += 1

    top_category = max(categories, key=categories.get)
    top_user = max(users, key=users.get)

    risk = "LOW"

    if high >= 3:
        risk = "HIGH"

    if high >= 10:
        risk = "CRITICAL"

    return {
        "risk": risk,
        "summary": f"{len(results)} matching threats discovered.",
        "patterns": [
            f"Most common attack: {top_category}",
            f"Most targeted user: {top_user}",
            f"Critical events: {high}"
        ],
        "recommendations": [
            "Investigate repeated attacks.",
            "Review affected accounts.",
            "Update blocking rules.",
            "Monitor correlated incidents."
        ]
    }
@app.post("/threat-hunt")
async def threat_hunt(request: ThreatHuntRequest):

    conn = get_conn()
    cur = conn.cursor()

    query = """
        SELECT
            id,
            timestamp,
            category,
            score,
            status,
            username,
            text
        FROM scans
        WHERE 1=1
    """

    params = []

    if request.category:
        query += " AND category=?"
        params.append(request.category)

    if request.severity:
        query += " AND status=?"
        params.append(request.severity)

    if request.username:
        query += " AND username=?"
        params.append(request.username)

    if request.status:
        query += " AND status=?"
        params.append(request.status)

    if request.min_score is not None:
        query += " AND score>=?"
        params.append(request.min_score)

    if request.max_score is not None:
        query += " AND score<=?"
        params.append(request.max_score)

    if request.keyword:
        query += " AND text LIKE ?"
        params.append(f"%{request.keyword}%")

    query += " ORDER BY timestamp DESC LIMIT 100"

    cur.execute(query, params)

    rows = cur.fetchall()

    columns = [d[0] for d in cur.description]

    results = [
        dict(zip(columns, row))
        for row in rows
    ]

    conn.close()

    analysis = ai_threat_hunter(results)

    save_threat_hunt(
        analyst="developer",
        category=request.category,
        severity=request.severity,
        keyword=request.keyword,
        result_count=len(results),
        risk=analysis["risk"]
    )

    return {
        "success": True,
        "count": len(results),
        "analysis": analysis,
        "results": results
    }
@app.post("/incident/update")
def update_incident(data: IncidentUpdate):

    result = update_incident_status(
        data.incident_id,
        data.status,
        data.notes
    )

    return {
        "success": True,
        "updated": result
    }
@app.get("/analyst/dashboard")
def analyst_dashboard():

    return {
        "active_incidents": len(ATTACK_TIMELINE),
        "recent_events": list(EVENT_STREAM.keys()),
        "system_status": soc_metrics()["status"]
    }
def triage_incident(score: float):

    if score >= 85:
        return "P1 - CRITICAL"
    elif score >= 70:
        return "P2 - HIGH"
    elif score >= 50:
        return "P3 - MEDIUM"
    return "P4 - LOW"
@app.get("/enterprise/summary")
def enterprise_summary():

    return {
        "users": len(USER_ROLES),
        "event_stream_size": sum(len(v) for v in EVENT_STREAM.values()),
        "incident_count": len(ATTACK_TIMELINE),
        "soc_status": soc_metrics()["status"]
    }
@app.get("/siem/search")
def siem_search(event_type: str = "raw"):

    return {
        "type": event_type,
        "results": EVENT_STREAM.get(event_type, [])
    }
@app.get("/siem/dashboard")
def siem_dashboard():

    return {
        "raw_events": len(EVENT_STREAM["raw_events"]),
        "processed": len(EVENT_STREAM["processed_events"]),
        "incidents": len(EVENT_STREAM["incidents"]),
        "alerts": len(EVENT_STREAM.get("alerts", [])),
        "status": "PRODUCTION_SIEM_ACTIVE"
    }
@app.get("/intelligence-dashboard")
def intelligence_dashboard():

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "velocity": get_threat_velocity(),
        "anomaly": get_threat_anomaly_score(),
        "soc_core": get_soc_intelligence_core(),
        "trends": get_threat_trends()
    }
@app.get("/threat-graph")
def threat_graph():
    return {
        "nodes": len(ATTACK_GRAPH["nodes"]),
        "edges": len(ATTACK_GRAPH["edges"]),
        "graph": ATTACK_GRAPH
    }
@app.get("/breach-forecast")
def breach_forecast():

    return {
        "prediction": predict_breach_risk(),
        "timestamp": datetime.utcnow().isoformat()
    }
@app.get("/attack-graph")
def attack_graph():

    # Live graph built during analysis
    graph = get_graph()

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, category, risk_score
        FROM scans
        ORDER BY id DESC
        LIMIT 100
    """)

    rows = cur.fetchall()
    conn.close()

    existing = {n["id"] for n in graph["nodes"]}

    for row in rows:

        scan_id = f"SCAN-{row['id']}"

        if scan_id not in existing:

            graph["nodes"].append({
                "id": scan_id,
                "type": "scan",
                "category": row["category"],
                "score": row["risk_score"] or 0
            })

    return {
        "nodes": graph["nodes"],
        "links": graph["edges"]
    }
@app.get("/ioc-intelligence")
async def ioc_intelligence():

    return {
        "ips": IOC_DATABASE["ips"],
        "domains": IOC_DATABASE["domains"],
        "emails": IOC_DATABASE["emails"],
        "urls": IOC_DATABASE["urls"],
        "hashes": IOC_DATABASE["hashes"]
    }
@app.get("/incidents/live")
def live_incidents():

    incidents = get_incidents()

    return incidents[:20]
@app.get("/graph-test")
def graph_test():
    soc_autonomous_orchestrator("Test", 90, "debug123")
    return ATTACK_GRAPH
@app.get("/debug-threat-graph")
def debug_threat_graph():
    return ATTACK_GRAPH
@app.get("/ui/dashboard")
def ui_dashboard():
    return {
        "kpis": {
            "scans": len(SOC_MEMORY["recent_incidents"]),
            "alerts": SOC_MEMORY.get("alerts_count", 0),
            "incidents": SOC_MEMORY.get("incidents_count", 0),
            "risk_score": SOC_REASONING_STATE["risk_bias"]
        },
        "status": "LIVE",
        "timestamp": datetime.utcnow().isoformat()
    }
@app.get("/ui/attack-graph")
def ui_attack_graph():

    nodes = []

    raw_nodes = ATTACK_GRAPH.get("nodes", {})

    if isinstance(raw_nodes, dict):

        iterator = raw_nodes.items()

    else:

        iterator = [
            (n.get("id"), n)
            for n in raw_nodes
        ]


    for node_id, node in iterator:

        if not node:
            continue

        nodes.append({

            "id": str(node_id),

            "category": node.get(
                "category",
                "Unknown"
            ),

            "score": node.get(
                "max_score",
                node.get("score",0)
            ),

            "count": node.get(
                "count",
                1
            )

        })


        links = []

    for edge in ATTACK_GRAPH.get("edges", []):

        source = edge.get("source")
        target = edge.get("target")

        if not source or not target:
            continue

        if source == "None" or target == "None":
            continue

        if isinstance(raw_nodes, dict):
            if source not in raw_nodes:
                continue

            if target not in raw_nodes:
                continue

        links.append({
            "source": source,
            "target": target
        })

    return {
        "nodes":nodes,
        "links":links
    }
@app.get("/ui/incident-timeline/{corr_id}")
def ui_incident_timeline(corr_id: str):
    return {
        "correlation_id": corr_id,
        "timeline": get_attack_timeline(corr_id),
        "status": "ACTIVE"
    }
@app.websocket("/ws/soc")
async def soc_stream(websocket: WebSocket):

    print("ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â¥ /ws/soc CONNECTED")

    await manager.connect(websocket)

    print("ACTIVE =", len(manager.active_connections))

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print("DISCONNECTED")


@app.get("/security-events")
def security_events(limit: int = 100, tenant_id: str | None = None):
    return {
        "events": get_security_events(
            limit=limit,
            tenant_id=tenant_id,
        )
    }


@app.get("/security-events/event/{event_id}")
def security_event(event_id: str):
    event = get_security_event(event_id)

    if not event:
        return {
            "success": False,
            "error": "SECURITY_EVENT_NOT_FOUND",
            "event_id": event_id,
        }

    return {
        "success": True,
        "event": event,
    }

@app.get("/attack-campaigns")
def attack_campaigns(
    limit: int = 50,
    tenant_id: str | None = None,
):
    return {
        "campaigns": get_attack_campaigns(
            tenant_id=tenant_id,
            limit=limit,
        )
    }


@app.get("/attack-campaigns/{campaign_id}")
def attack_campaign(campaign_id: str):
    campaign = get_attack_campaign(campaign_id)

    if not campaign:
        return {
            "success": False,
            "error": "CAMPAIGN_NOT_FOUND",
            "campaign_id": campaign_id,
        }

    return {
        "success": True,
        "campaign": campaign,
    }


@app.get("/attack-campaigns/{campaign_id}/investigation")
def attack_campaign_investigation(campaign_id: str):
    campaign = get_attack_campaign(campaign_id)

    if not campaign:
        return {
            "success": False,
            "error": "CAMPAIGN_NOT_FOUND",
            "campaign_id": campaign_id,
        }

    cluster_id = campaign.get("cluster_id")
    cluster = (
        get_correlation_cluster(cluster_id)
        if cluster_id
        else None
    )

    response_events = []

    try:
        correlation_ids = set()

        for member in (cluster or {}).get("members", []):
            event_id = member.get("event_id")

            if not event_id:
                continue

            source_event = get_security_event(event_id)

            if source_event:
                correlation_id = source_event.get("correlation_id")

                if correlation_id:
                    correlation_ids.add(correlation_id)

        fabric_events = get_security_events(
            limit=500,
            tenant_id=campaign.get("tenant_id"),
        )

        for fabric_event in fabric_events:
            if fabric_event.get("event_type") != "auto_response_event":
                continue

            same_campaign = (
                fabric_event.get("campaign_id") == campaign_id
            )

            same_correlation = (
                fabric_event.get("correlation_id")
                in correlation_ids
            )

            if same_campaign or same_correlation:
                response_events.append(fabric_event)

    except Exception as response_error:
        print(
            "[42.22] Campaign response lookup failed:",
            response_error,
        )

    response_status = (
        "EXECUTED"
        if any(
            event.get("status") == "EXECUTED"
            for event in response_events
        )
        else (
            "BACKFILLED"
            if response_events
            else "NO_RESPONSE_RECORDED"
        )
    )

    investigation = {
        "campaign": campaign,
        "cluster": cluster,
        "timeline": get_campaign_timeline(campaign_id),
        "response": {
            "status": response_status,
            "event_count": len(response_events),
            "events": response_events,
        },
        "threat_dna": None,
        "attack_graph": None,
        "digital_twin": None,
        "replay": None,
        "links": {
            "campaign_id": campaign_id,
            "cluster_id": cluster_id,
        },
    }

    return {
        "success": True,
        "investigation": investigation,
    }


@app.get("/campaigns")
def campaigns():

    return correlation_get_campaigns()
@app.get("/prediction")
def prediction():

    return predict()
def predict_next_attack():

    patterns = SOC_MEMORY["threat_patterns"]

    if not patterns:
        return {
            "prediction": "UNKNOWN",
            "confidence": 0
        }

    category = max(
        patterns,
        key=lambda x: patterns[x]["count"]
    )

    confidence = min(
        99,
        patterns[category]["count"] * 10
    )

    prediction = {
        "prediction": category,
        "confidence": confidence,
        "expected_score": round(
            patterns[category]["avg_score"],
            2
        ),
        "generated": now_ts()
    }

    THREAT_PREDICTION["predictions"].append(prediction)

    if len(THREAT_PREDICTION["predictions"]) > 100:
        THREAT_PREDICTION["predictions"] = (
            THREAT_PREDICTION["predictions"][-100:]
        )

    return prediction
@app.get("/prediction")
def get_prediction():
    return predict_next_attack()
@app.get("/reports")
def get_reports():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            created_at,
            category,
            severity,
            status,
            assigned_to
        FROM incidents
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    conn.close()

    reports = []

    for row in rows:
        reports.append({
            "id": row[0],
            "created_at": row[1],
            "category": row[2],
            "severity": row[3],
            "status": row[4],
            "assigned_to": row[5]
        })

    return reports
@app.get("/reports/pdf")
def reports_pdf():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id,
               created_at,
               category,
               severity,
               status,
               assigned_to
        FROM incidents
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    conn.close()

    filename = "incident_report.pdf"

    data = [[
        "ID",
        "Date",
        "Category",
        "Severity",
        "Status",
        "Assigned"
    ]]

    for r in rows:
        data.append([
            r[0],
            str(r[1]),
            r[2],
            r[3],
            r[4],
            r[5] or "Unassigned"
        ])

    pdf = SimpleDocTemplate(filename)
    table = Table(data)
    pdf.build([table])

    return FileResponse(
        filename,
        filename="incident_report.pdf",
        media_type="application/pdf"
    )
@app.get("/reports/csv")
def reports_csv():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id,
               created_at,
               category,
               severity,
               status,
               assigned_to
        FROM incidents
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    conn.close()

    filename = "incident_report.csv"

    with open(filename, "w", newline="", encoding="utf-8") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "ID",
            "Date",
            "Category",
            "Severity",
            "Status",
            "Assigned To"
        ])

        writer.writerows(rows)

    return FileResponse(
        filename,
        filename="incident_report.csv",
        media_type="text/csv"
    )
@app.get("/hunt")
async def hunt(query: str = ""):
    conn = get_conn()
    cur = conn.cursor()

    q = f"%{query}%"

    cur.execute("""
        SELECT
            id,
            category,
            severity,
            status,
            message,
            created_at
        FROM incidents
        WHERE
            category LIKE ?
            OR message LIKE ?
            OR severity LIKE ?
            OR status LIKE ?
        ORDER BY id DESC
    """, (q, q, q, q))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "category": r[1],
            "severity": r[2],
            "status": r[3],
            "message": r[4],
            "created_at": r[5]
        }
        for r in rows
    ]
@app.get("/analytics")
def analytics():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT category, COUNT(*)
        FROM incidents
        GROUP BY category
    """)
    categories = cur.fetchall()

    cur.execute("""
        SELECT severity, COUNT(*)
        FROM incidents
        GROUP BY severity
    """)
    severities = cur.fetchall()

    cur.execute("""
        SELECT status, COUNT(*)
        FROM incidents
        GROUP BY status
    """)
    statuses = cur.fetchall()

    conn.close()

    return {
        "categories": [
            {"name": c[0], "count": c[1]}
            for c in categories
        ],
        "severities": [
            {"name": s[0], "count": s[1]}
            for s in severities
        ],
        "statuses": [
            {"name": s[0], "count": s[1]}
            for s in statuses
        ]
    }
@app.get("/customer/dashboard")
def customer_dashboard(tenant_id: str = "demo"):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) AS count FROM scans WHERE tenant_id = ?",
        (tenant_id,)
    )
    total_scans = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT
            id,
            message,
            level,
            created_at
        FROM alerts
        WHERE tenant_id = ?
        ORDER BY id DESC
        LIMIT 5
    """, (tenant_id,))

    alerts = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT COUNT(*) AS count FROM alerts WHERE tenant_id = ?",
        (tenant_id,)
    )
    total_alerts = cursor.fetchone()["count"]

    cursor.execute(
        "SELECT COUNT(*) AS count FROM incidents WHERE tenant_id = ?",
        (tenant_id,)
    )
    total_incidents = cursor.fetchone()["count"]

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE tenant_id = ? AND status = 'OPEN'
        """,
        (tenant_id,)
    )
    open_incidents = cursor.fetchone()["count"]

    score = max(0, 100 - open_incidents * 10)

    conn.close()

    return {
        "tenant_id": tenant_id,
        "security_score": score,
        "total_scans": total_scans,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "alerts": alerts,
        "recent_alerts": alerts
    }
@app.get("/executive/dashboard")
def executive_dashboard():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM scans")
    total_scans = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM alerts")
    total_alerts = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM incidents")
    total_incidents = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
        WHERE status='OPEN'
    """)
    open_incidents = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT AVG(risk_score) AS avg_risk
        FROM scans
    """)
    avg_risk = cursor.fetchone()["avg_risk"] or 0

    security_score = max(0, 100 - avg_risk)

    conn.close()

    return {
        "security_score": round(security_score, 2),
        "enterprise_risk": round(avg_risk, 2),
        "total_scans": total_scans,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents
    }

@app.get("/executive/risk-trend")
def executive_risk_trend():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            DATE(created_at) AS day,
            ROUND(AVG(risk_score),2) AS risk
        FROM scans
        GROUP BY DATE(created_at)
        ORDER BY day
    """)

    data = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return data
@app.get("/executive/threat-distribution")
def executive_threat_distribution():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            category,
            COUNT(*) AS value
        FROM scans
        GROUP BY category
        ORDER BY value DESC
    """)

    data = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return data
@app.get("/executive/incidents")
def executive_incidents():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            category,
            risk_score,
            status,
            created_at
        FROM incidents
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return rows
@app.get("/executive/briefing")
def executive_briefing():

    kpi = executive_kpis()

    score = kpi.get("security_score", 0)
    risk = kpi.get("enterprise_risk", 100 - score)

    if score >= 80:
        posture = "Healthy"
    elif score >= 50:
        posture = "Moderate"
    else:
        posture = "Critical"

    if risk >= 70:
        recommendation = (
            "Immediate executive intervention recommended."
        )
    elif risk >= 40:
        recommendation = (
            "Prioritize high-risk incident remediation."
        )
    else:
        recommendation = (
            "Maintain continuous monitoring."
        )

    summary = (
        f"Enterprise security posture is {posture}. "
        f"Security score is {score:.2f}%. "
        f"There are {kpi.get('open_incidents', 0)} open incidents. "
        f"Enterprise risk is {risk:.2f}. "
        f"{recommendation}"
    )

    return {
        "posture": posture,
        "summary": summary,
        "recommendation": recommendation
    }
@app.get("/customer/attack-trend")
def customer_attack_trend(tenant_id: str):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            TO_CHAR(incidents.created_at, 'HH24:00') AS hour,
            COUNT(*) AS attacks,
            AVG(scans.risk_score) AS avg_score
        FROM incidents
        JOIN scans
            ON incidents.scan_id = scans.id
        WHERE incidents.tenant_id = ?
        GROUP BY hour
        ORDER BY hour ASC
    """, (tenant_id,))

    rows = cursor.fetchall()

    conn.close()

    trend = []

    for row in rows:
        trend.append({
            "time": row["hour"],
            "attacks": row["attacks"],
            "score": round(row["avg_score"], 2)
        })

    return trend
@app.get("/customer/incidents")
def customer_incidents(tenant_id: str):
    return get_incidents(tenant_id)
class CustomerIncidentUpdate(BaseModel):
    status: str


@app.put("/customer/incidents/{incident_id}")
def update_customer_incident(
    incident_id: int,
    payload: CustomerIncidentUpdate
):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE incidents
        SET status = ?
        WHERE id = ?
    """, (
        payload.status,
        incident_id
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "incident_id": incident_id,
        "status": payload.status
    }
@app.get("/customer/trends")
def customer_trends(tenant_id: str = "demo"):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            DATE(created_at) AS day,
            COUNT(*) AS count
        FROM scans
        WHERE tenant_id=?
        GROUP BY DATE(created_at)
        ORDER BY day
    """, (tenant_id,))

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
@app.get("/customer/categories")
def customer_categories(tenant_id: str = "demo"):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            category,
            COUNT(*) AS count
        FROM scans
        WHERE tenant_id=?
        GROUP BY category
        ORDER BY count DESC
    """, (tenant_id,))

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
@app.get("/customer/status")
def customer_status(tenant_id: str = "demo"):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            status,
            COUNT(*) AS count
        FROM incidents
        WHERE tenant_id=?
        GROUP BY status
    """, (tenant_id,))

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
@app.get("/customer/alerts")
def customer_alerts(tenant_id: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM alerts
        WHERE tenant_id=?
        ORDER BY id DESC
        LIMIT 20
    """, (tenant_id,))

    rows = cur.fetchall()

    conn.close()

    return [dict(r) for r in rows]
@app.get("/debug/customer/{tenant_id}")
def debug_customer(tenant_id: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM scans WHERE tenant_id=?", (tenant_id,))
    scans = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE tenant_id=?", (tenant_id,))
    alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE tenant_id=?", (tenant_id,))
    incidents = cur.fetchone()[0]

    conn.close()

    return {
        "tenant_id": tenant_id,
        "scans": scans,
        "alerts": alerts,
        "incidents": incidents
    }
@app.get("/debug/tenants")
def debug_tenants():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT tenant_id, COUNT(*) total
        FROM scans
        GROUP BY tenant_id
    """)
    scans = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT tenant_id, COUNT(*) total
        FROM alerts
        GROUP BY tenant_id
    """)
    alerts = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT tenant_id, COUNT(*) total
        FROM incidents
        GROUP BY tenant_id
    """)
    incidents = [dict(r) for r in cur.fetchall()]

    conn.close()

    return {
        "scans": scans,
        "alerts": alerts,
        "incidents": incidents
    }
@app.get("/executive/kpis")
def executive_kpis():
    return get_executive_kpis()
@app.get("/executive/live-feed")
def executive_live_feed():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            category,
            risk_score,
            status,
            created_at
        FROM incidents
        ORDER BY id DESC
        LIMIT 10
    """)

    rows = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return rows
@app.post("/executive/copilot")
def executive_copilot(data: dict):

    question = data.get("question", "")

    kpis = get_executive_kpis()

    answer = f"""
Enterprise security posture analysis:

Security Score: {kpis.get('security_score', 'N/A')}%

Enterprise Risk:
{kpis.get('enterprise_risk', 'N/A')}

Total Incidents:
{kpis.get('total_incidents', 0)}

Open Incidents:
{kpis.get('open_incidents', 0)}

Analysis:
The current risk level is influenced by active incidents,
threat activity and historical scan patterns.

Recommendation:
Review high-risk incidents and prioritize remediation.
"""

    return {
        "answer": answer
    }
@app.get("/executive/decision")
def executive_decision():

    kpi = get_executive_kpis()

    risk = kpi.get("enterprise_risk", 0)
    top = kpi.get("top_threat", "Unknown")

    if risk >= 75:
        level = "Critical"
        recommendation = "Immediate executive intervention required. Prioritize high-risk incidents."
        change = "Increasing"
        
    elif risk >= 50:
        level = "High"
        recommendation = "Review active threats and accelerate remediation."
        change = "Elevated"

    elif risk >= 25:
        level = "Medium"
        recommendation = "Monitor threat activity and review security controls."
        change = "Stable"

    else:
        level = "Low"
        recommendation = "Security posture is healthy. Continue monitoring."
        change = "Improving"


    return {
        "level": level,
        "top_threat": top,
        "risk_change": change,
        "recommendation": recommendation,
        "enterprise_risk": risk
    }
@app.get("/executive/priority-queue")
def executive_priority_queue():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            category,
            risk_score,
            status
        FROM incidents
        ORDER BY risk_score DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    conn.close()

    priority = []

    for row in rows:

        risk = row["risk_score"]

        if risk >= 90:
            action = "Immediate containment required"

        elif risk >= 70:
            action = "Investigate and remediate"

        elif risk >= 50:
            action = "Monitor closely"

        else:
            action = "Continue monitoring"


        priority.append({
            "id": row["id"],
            "category": row["category"],
            "risk_score": risk,
            "status": row["status"],
            "action": action
        })

    return priority
@app.get("/executive/actions")
def executive_actions():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            category,
            risk_score,
            status
        FROM incidents
        ORDER BY risk_score DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    conn.close()

    actions = []

    for row in rows:

        risk = row["risk_score"]

        if risk >= 90:
            actions.append({
                "title": f"Critical {row['category']} Incident #{row['id']}",
                "priority": "CRITICAL",
                "action": "Contain threat immediately and assign security response team"
            })

        elif risk >= 70:
            actions.append({
                "title": f"High Risk {row['category']} Incident #{row['id']}",
                "priority": "HIGH",
                "action": "Investigate incident and begin remediation"
            })

        else:
            actions.append({
                "title": f"Monitor {row['category']} Incident #{row['id']}",
                "priority": "LOW",
                "action": "Continue monitoring activity"
            })

    return actions
@app.get("/executive/escalation-matrix")
def executive_escalation_matrix():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT risk_score
        FROM incidents
    """)

    rows = cursor.fetchall()

    conn.close()

    critical = 0
    high = 0
    medium = 0
    low = 0

    for row in rows:

        risk = row["risk_score"]

        if risk >= 90:
            critical += 1

        elif risk >= 70:
            high += 1

        elif risk >= 50:
            medium += 1

        else:
            low += 1

    if critical > 0:
        sla = "Immediate response required (< 15 minutes)"

    elif high > 0:
        sla = "Priority response required (< 1 hour)"

    elif medium > 0:
        sla = "Review within 24 hours"

    else:
        sla = "Normal monitoring"


    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "sla": sla,
        "total": len(rows)
    }
@app.get("/executive/summary")
def executive_summary():

    kpi = get_executive_kpis()

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE risk_score >= 90
    """)

    critical = cursor.fetchone()[0]

    conn.close()

    risk = kpi["enterprise_risk"]

    if risk >= 70:
        posture = "Critical"

    elif risk >= 40:
        posture = "Medium"

    else:
        posture = "Low"


    if critical > 0:
        action = "Immediate review of critical incidents required."

    else:
        action = "Continue monitoring security activity."


    return {
        "posture": posture,
        "security_score": kpi["security_score"],
        "open_incidents": kpi.get("open_incidents", 0),
        "critical_threats": critical,
        "action": action
    }
@app.get("/executive/threat-intelligence")
def executive_threat_intelligence():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT category, COUNT(*) as total
        FROM incidents
        GROUP BY category
        ORDER BY total DESC
    """)

    threats = cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE risk_score >= 80
    """)

    high_risk = cursor.fetchone()[0]

    conn.close()


    if high_risk >= 5:
        trend = "Increasing"
        warning = "Threat activity is accelerating. Executive attention required."

    elif high_risk > 0:
        trend = "Stable"
        warning = "Threat activity remains active. Continue monitoring."

    else:
        trend = "Decreasing"
        warning = "Threat activity is under control."


    top = threats[0]["category"] if threats else "None"


    return {
        "top_threat": top,
        "high_risk_events": high_risk,
        "trend": trend,
        "warning": warning
    }
@app.get("/executive/prediction")
def executive_prediction():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT category, COUNT(*) as total
        FROM incidents
        WHERE risk_score >= 70
        GROUP BY category
        ORDER BY total DESC
        LIMIT 1
    """)

    row = cursor.fetchone()


    cursor.execute("""
        SELECT AVG(risk_score)
        FROM incidents
    """)

    avg = cursor.fetchone()[0] or 0

    conn.close()


    if row:
        predicted = row["category"]
    else:
        predicted = "No active threat"


    if avg >= 80:
        probability = 90
        forecast = "High probability of continued malicious activity."

    elif avg >= 50:
        probability = 65
        forecast = "Moderate threat activity expected."

    else:
        probability = 30
        forecast = "Low threat activity expected."


    return {
        "predicted_threat": predicted,
        "probability": probability,
        "forecast": forecast,
        "average_risk": round(avg,2)
    }
@app.get("/executive/remediation")
def executive_remediation():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, category, risk_score, status
        FROM incidents
        ORDER BY risk_score DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    conn.close()


    actions = []

    for row in rows:

        if row["risk_score"] >= 90:
            action = "Contain immediately and isolate affected assets"
            priority = "CRITICAL"

        elif row["risk_score"] >= 70:
            action = "Investigate source and begin remediation"
            priority = "HIGH"

        else:
            action = "Continue monitoring activity"
            priority = "LOW"


        actions.append({
            "id": row["id"],
            "category": row["category"],
            "risk_score": row["risk_score"],
            "status": row["status"],
            "priority": priority,
            "recommended_action": action
        })


    return actions
@app.get("/executive/incident/{incident_id}")
def executive_incident_detail(incident_id: int):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE id = ?
    """, (incident_id,))

    incident = cursor.fetchone()

    conn.close()


    if not incident:
        return {
            "error": "Incident not found"
        }


    risk = incident["risk_score"]


    if risk >= 90:
        severity = "CRITICAL"
        recommendation = (
            "Immediate containment required. "
            "Assign security response team."
        )

    elif risk >= 70:
        severity = "HIGH"
        recommendation = (
            "Investigate source and begin remediation."
        )

    else:
        severity = "LOW"
        recommendation = (
            "Continue monitoring activity."
        )


    return {
        "id": incident["id"],
        "category": incident["category"],
        "risk_score": risk,
        "status": incident["status"],
        "severity": severity,
        "created_at": incident["created_at"],
        "ai_recommendation": recommendation
    }
@app.get("/executive/compliance")
def executive_compliance():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status = 'OPEN'
    """)

    open_incidents = cursor.fetchone()[0]


    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
    """)

    alerts = cursor.fetchone()[0]


    conn.close()


    if open_incidents >= 40:
        score = 45
        status = "Needs Improvement"
        recommendation = (
            "Reduce open incidents and strengthen response controls."
        )

    elif open_incidents >= 10:
        score = 70
        status = "Moderate"
        recommendation = (
            "Improve incident closure rate and monitoring."
        )

    else:
        score = 90
        status = "Compliant"
        recommendation = (
            "Maintain current security governance controls."
        )


    return {
        "compliance_score": score,
        "status": status,
        "open_incidents": open_incidents,
        "total_alerts": alerts,
        "recommendation": recommendation
    }
@app.get("/executive/scorecard")
def executive_scorecard():

    kpi = get_executive_kpis()

    conn = get_conn()
    cursor = conn.cursor()


    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE risk_score >= 80
    """)

    high_risk = cursor.fetchone()[0]


    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status != 'OPEN'
    """)

    resolved = cursor.fetchone()[0]


    conn.close()


    detection = min(
        100,
        kpi["total_scans"]
    )


    response = min(
        100,
        resolved * 10
    )


    if kpi["enterprise_risk"] <= 30:
        maturity = "Advanced"

    elif kpi["enterprise_risk"] <= 60:
        maturity = "Developing"

    else:
        maturity = "Needs Improvement"


    overall = round(
        (
            detection +
            response +
            (100 - kpi["enterprise_risk"])
        ) / 3,
        2
    )


    return {

        "security_maturity": maturity,

        "overall_score": overall,

        "detection_capability": detection,

        "response_capability": response,

        "high_risk_events": high_risk

    }
@app.get("/executive/strategy")
def executive_strategy():

    conn = get_conn()
    cursor = conn.cursor()


    cursor.execute("""
        SELECT category, COUNT(*) as total
        FROM incidents
        GROUP BY category
        ORDER BY total DESC
        LIMIT 3
    """)

    threats = cursor.fetchall()


    cursor.execute("""
        SELECT AVG(risk_score)
        FROM incidents
    """)

    avg_risk = cursor.fetchone()[0] or 0


    conn.close()


    recommendations = []


    if avg_risk >= 70:

        recommendations.append(
            "Increase incident response capacity immediately."
        )

        recommendations.append(
            "Prioritize advanced threat detection controls."
        )


    elif avg_risk >= 40:

        recommendations.append(
            "Improve monitoring coverage and threat hunting."
        )

        recommendations.append(
            "Review security policies and access controls."
        )


    else:

        recommendations.append(
            "Maintain current security posture."
        )

        recommendations.append(
            "Continue proactive security monitoring."
        )


    top_threats = [
        row["category"]
        for row in threats
    ]


    return {

        "security_outlook":
            "Elevated Risk"
            if avg_risk >= 40
            else "Stable",


        "average_risk":
            round(avg_risk,2),


        "top_threats":
            top_threats,


        "strategic_recommendations":
            recommendations

    }
@app.get("/executive/board-report")
def executive_board_report():

    dashboard = executive_dashboard()
    briefing = executive_briefing()
    decision = executive_decision()
    compliance = executive_compliance()
    scorecard = executive_scorecard()
    strategy = executive_strategy()
    escalation = executive_escalation_matrix()
    actions = executive_actions()

    return {

        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "executive_summary": briefing,

        "enterprise_security": dashboard,

        "risk_decision": decision,

        "compliance": compliance,

        "security_scorecard": scorecard,

        "strategy": strategy,

        "escalation": escalation,

        "recommended_actions": actions

    }
@app.get("/executive/report/pdf")
def executive_pdf_report():

    dashboard = executive_dashboard()
    briefing = executive_briefing()
    decision = executive_decision()
    compliance = executive_compliance()
    scorecard = executive_scorecard()
    strategy = executive_strategy()
    escalation = executive_escalation_matrix()

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "<b>SafeChat AI Executive Security Report</b>",
            styles["Title"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Executive Summary",
            styles["Heading1"]
        )
    )

    story.append(
        Paragraph(
            briefing["summary"],
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 15))

    data = [

        ["Metric", "Value"],

        ["Security Score", str(dashboard["security_score"]) + "%"],

        ["Enterprise Risk", str(dashboard["enterprise_risk"])],

        ["Total Scans", str(dashboard["total_scans"])],

        ["Alerts", str(dashboard["total_alerts"])],

        ["Incidents", str(dashboard["total_incidents"])],

        ["Open Incidents", str(dashboard["open_incidents"])],

        ["Risk Level", decision["level"]],

        ["Top Threat", decision["top_threat"]],

        ["Compliance", compliance["status"]],

        ["Compliance Score", str(compliance["compliance_score"]) + "%"],

        ["Security Maturity", scorecard["security_maturity"]],

        ["Overall Security Score", str(scorecard["overall_score"]) + "%"]

    ]

    table = Table(data)

    table.setStyle(

        TableStyle([

            ("BACKGROUND", (0,0), (-1,0), colors.darkblue),

            ("TEXTCOLOR", (0,0), (-1,0), colors.white),

            ("GRID", (0,0), (-1,-1), 1, colors.grey),

            ("BACKGROUND", (0,1), (-1,-1), colors.beige),

            ("BOTTOMPADDING", (0,0), (-1,0), 10),

            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold")

        ])

    )

    story.append(table)

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Strategic Recommendations",
            styles["Heading1"]
        )
    )

    for item in strategy["strategic_recommendations"]:

        story.append(

            Paragraph(
                "- " + item,
                styles["BodyText"]
            )

        )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Executive Recommendation",
            styles["Heading1"]
        )
    )

    story.append(
        Paragraph(
            briefing["recommendation"],
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "<b>Threat Escalation SLA</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            escalation["sla"],
            styles["BodyText"]
        )
    )

    doc.build(story)

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            "attachment; filename=Executive_Security_Report.pdf"
        }
    )
@app.get("/executive/threat-map")
def executive_threat_map():
    return get_executive_threat_map()
def get_executive_risk_forecast():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT risk_score
        FROM incidents
        ORDER BY id ASC
    """)

    rows = cur.fetchall()
    conn.close()

    if len(rows) < 2:

        return [
            {
                "day": "Today",
                "risk": 0
            }
        ]

    risks = [r["risk_score"] for r in rows]

    X = np.arange(len(risks)).reshape(-1, 1)
    y = np.array(risks)

    model = LinearRegression()
    model.fit(X, y)

    future = []

    total_days = len(risks) + 7

    for i in range(total_days):

        if i < len(risks):

            value = risks[i]

        else:

            value = float(model.predict([[i]])[0])

        value = max(0, min(100, round(value, 2)))

        future.append({
            "day": f"D{i+1}",
            "risk": value
        })

    return future
@app.post("/executive/simulate")
def executive_simulation(data: dict):

    attack = data.get("attack", "Unknown")
    increase = float(data.get("increase", 0))

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT AVG(risk_score) AS risk
        FROM incidents
    """)

    row = cur.fetchone()
    conn.close()

    current = round(row["risk"] or 0, 2)

    predicted = min(100, round(current + (increase * 0.6), 2))

    if predicted >= 85:
        level = "Critical"
    elif predicted >= 70:
        level = "High"
    elif predicted >= 40:
        level = "Medium"
    else:
        level = "Low"

    return {
        "attack": attack,
        "current_risk": current,
        "predicted_risk": predicted,
        "change": round(predicted - current, 2),
        "level": level,
        "recommendation": f"Increase monitoring and containment for {attack}."
    }
@app.post("/executive/approve-action/{incident_id}")
def approve_action(incident_id: int):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE incidents
        SET status='Contained'
        WHERE id=?
        """,
        (incident_id,)
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "incident": incident_id,
        "status": "Contained",
        "message": "SOC AI has automatically contained this threat."
    }
@app.get("/executive/kpi-history")
def executive_kpi_history():

    return [
        {
            "time": "Mon",
            "security_score": 92,
            "enterprise_risk": 24
        },
        {
            "time": "Tue",
            "security_score": 91,
            "enterprise_risk": 28
        },
        {
            "time": "Wed",
            "security_score": 89,
            "enterprise_risk": 33
        },
        {
            "time": "Thu",
            "security_score": 94,
            "enterprise_risk": 18
        },
        {
            "time": "Fri",
            "security_score": 96,
            "enterprise_risk": 14
        }
    ]
@app.get("/executive/live-metrics")
def executive_live_metrics():

    incidents = get_incidents()

    active = len(incidents)

    critical = sum(
    1
    for i in incidents
    if float(i.get("risk_score") or 0) >= 90
)

    blocked = sum(
        1
        for i in incidents
        if i.get("status") == "Blocked"
    )

    return {
        "active_threats": active,
        "critical_alerts": critical,
        "blocked_attacks": blocked,
        "ai_decisions": active
    }
def build_executive_context():

    incidents = get_incidents()

    total = len(incidents)

    if total == 0:
        return {
            "security_score": 100,
            "enterprise_risk": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "incidents": [],
            "average_risk": 0
        }

    scores = [i.get("risk_score", i.get("score", 0)) for i in incidents]

    critical = sum(1 for s in scores if s >= 90)
    high = sum(1 for s in scores if 70 <= s < 90)
    medium = sum(1 for s in scores if 40 <= s < 70)
    low = sum(1 for s in scores if s < 40)

    avg = round(sum(scores) / len(scores), 2)

    security_score = round(100 - avg, 2)

    return {
        "security_score": security_score,
        "enterprise_risk": avg,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "average_risk": avg,
        "incidents": incidents
    }
def executive_ai_decision():

    ctx = build_executive_context()

    risk = ctx["enterprise_risk"]

    actions = []

    if risk >= 90:

        actions.extend([
            "Activate Incident Response Team",
            "Notify CEO and Board",
            "Isolate affected systems",
            "Freeze privileged accounts"
        ])

        level = "CRITICAL"

    elif risk >= 70:

        actions.extend([
            "Escalate to SOC Manager",
            "Increase monitoring",
            "Block malicious IPs",
            "Start forensic collection"
        ])

        level = "HIGH"

    elif risk >= 40:

        actions.extend([
            "Investigate alerts",
            "Continue monitoring",
            "Review firewall rules"
        ])

        level = "MEDIUM"

    else:

        actions.extend([
            "Normal Operations",
            "Routine monitoring"
        ])

        level = "LOW"

    return {
        "risk_level": level,
        "enterprise_risk": risk,
        "recommended_actions": actions,
        "confidence": 97
    }

def get_ai_executive_decision():

    incidents = get_incidents()

    if not incidents:
        return {
            "decision": "System operating normally.",
            "priority": "LOW",
            "confidence": 100
        }

    high = sum(
        1
        for i in incidents
        if float(i.get("score", 0)) >= 80
    )

    critical = sum(
    1
    for i in incidents
    if float(i.get("risk_score") or 0) >= 90
)

    if critical >= 5:
        return {
            "decision": "Immediate executive escalation recommended.",
            "priority": "CRITICAL",
            "confidence": 99
        }

    if high >= 5:
        return {
            "decision": "Increase SOC monitoring and activate incident response.",
            "priority": "HIGH",
            "confidence": 96
        }

    return {
        "decision": "Continue monitoring. Current cyber risk is acceptable.",
        "priority": "MEDIUM",
        "confidence": 92
    }
@app.get("/executive/ai-decision")
def executive_ai_decision():
    return get_ai_executive_decision()
@app.get("/executive/risk-forecast")
def executive_risk_forecast():
    return get_executive_risk_forecast()
@app.get("/executive/attack-replay")
def executive_attack_replay():
    return get_replay()
@app.websocket("/ws/incidents")
async def ws_incidents(websocket: WebSocket):
    await websocket.accept()

    while True:
        data = {
            "id": random.randint(1000, 9999),
            "type": "Malware",
            "severity": random.randint(10, 100)
        }

        try:
            await websocket.send_text(json.dumps(data))
        except Exception:
            # Client disconnected
            return

        await asyncio.sleep(3)
@app.get("/seed-incidents")
def seed_incidents():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incidents (type, severity)
        VALUES
        ('Malware', 90),
        ('Phishing', 70),
        ('IP', 40),
        ('User', 20),
        ('Device', 60),
    """)
    for ioc in iocs:
        cursor.execute(
        """
        INSERT INTO threat_intel(
            incident_id,
            ioc,
            type,
            reputation,
            risk_score
        )
        VALUES (?,?,?,?,?)
        """,
        (
            incident_id,
            ioc["ioc"],
            ioc["type"],
            ioc.get("reputation","UNKNOWN"),
            ioc.get("risk_score",0)
        )
    )

    conn.commit()
    conn.close()

    return {"status": "seeded"}
@app.get("/customer/iocs")
def customer_iocs():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            indicator,
            category,
            score,
            confidence,
            sightings,
            campaign,
            first_seen,
            last_seen
        FROM threat_intelligence
        ORDER BY score DESC, confidence DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]
@app.get("/debug/incidents-schema")
def debug_incidents_schema():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(incidents)")

    rows = cursor.fetchall()

    conn.close()

    return [dict(r) for r in rows]
@app.get("/customer/incidents/{incident_id}/intel")
def incident_intel(incident_id:int):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT threat_intel
        FROM incidents
        WHERE id=?
        """,
        (incident_id,)
    )

    row = cursor.fetchone()

    conn.close()

    if not row:
        return {
            "error":"Incident not found"
        }

    return {
        "incident_id":incident_id,
        "intel":json.loads(row["threat_intel"] or "[]")
    }
@app.get("/executive/users")
def executive_users():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            full_name,
            email,
            role,
            tenant_id,
            created_at
        FROM users
        ORDER BY created_at DESC
    """)

    users = []

    for row in cursor.fetchall():
        user = dict(row)

        # Do not expose passwords or authentication tokens
        user["active"] = any(
            session_user
            and session_user.get("username") == user["username"]
            for session_user in ACTIVE_SESSIONS.values()
        )

        users.append(user)

    conn.close()

    return {
        "total_users": len(users),
        "users": users
    }



# ============================================================
# ADMIN USER MANAGEMENT API
# ============================================================

def require_admin(user=Depends(get_current_user)):
    if str(user.get("role", "")).lower() != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required."
        )
    return user

@app.get("/admin/users")
def admin_users(user=Depends(require_admin)):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(db_sql("""
            SELECT
                id,
                username,
                full_name,
                email,
                role,
                tenant_id,
                status,
                is_active,
                suspended_at,
                blocked_at,
                session_version,
                password_reset_required,
                mfa_enabled,
                created_at
            FROM users
            ORDER BY id DESC
        """))

        users = [dict(row) for row in cursor.fetchall()]

        return {
            "success": True,
            "total_users": len(users),
            "users": users
        }

    finally:
        conn.close()


@app.get("/admin/users/{user_id}")
def admin_user_details(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(db_sql("""
            SELECT
                id,
                username,
                full_name,
                email,
                role,
                tenant_id,
                status,
                is_active,
                suspended_at,
                blocked_at,
                session_version,
                password_reset_required,
                mfa_enabled,
                created_at
            FROM users
            WHERE id = ?
        """), (user_id,))

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        return {
            "success": True,
            "user": dict(target)
        }

    finally:
        conn.close()


@app.patch("/admin/users/{user_id}/status")
def admin_change_user_status(
    user_id: int,
    status: str,
    user=Depends(require_admin)
):
    status = status.strip().lower()

    allowed = {
        "active",
        "suspended",
        "blocked"
    }

    if status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Status must be active, suspended, or blocked."
        )

    if user.get("id") == user_id and status != "active":
        raise HTTPException(
            status_code=400,
            detail="An administrator cannot suspend or block their own account."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT id, username
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        now = datetime.utcnow().isoformat()

        if status == "active":
            cursor.execute(
                db_sql("""
                    UPDATE users
                    SET status = 'active',
                        is_active = 1,
                        suspended_at = NULL,
                        blocked_at = NULL,
                        session_version = COALESCE(session_version, 0) + 1
                    WHERE id = ?
                """),
                (user_id,)
            )

        elif status == "suspended":
            cursor.execute(
                db_sql("""
                    UPDATE users
                    SET status = 'suspended',
                        is_active = 0,
                        suspended_at = ?,
                        session_version = COALESCE(session_version, 0) + 1
                    WHERE id = ?
                """),
                (now, user_id)
            )

        else:
            cursor.execute(
                db_sql("""
                    UPDATE users
                    SET status = 'blocked',
                        is_active = 0,
                        blocked_at = ?,
                        session_version = COALESCE(session_version, 0) + 1
                    WHERE id = ?
                """),
                (now, user_id)
            )

        conn.commit()

        try:
            create_audit_log(
                action=f"USER_STATUS_CHANGE:{status}",
                user=user.get("username"),
                message=f"Admin changed user {target['username']} to {status}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "user_id": user_id,
            "status": status
        }

    finally:
        conn.close()


@app.post("/admin/users/{user_id}/force-logout")
def admin_force_logout(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT username
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        cursor.execute(
            db_sql("""
                UPDATE users
                SET session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (user_id,)
        )

        conn.commit()

        try:
            create_audit_log(
                action="FORCE_LOGOUT",
                user=user.get("username"),
                message=f"Admin revoked all sessions for {target['username']}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "message": "All user sessions have been revoked."
        }

    finally:
        conn.close()


@app.patch("/admin/users/{user_id}/role")
def admin_change_user_role(
    user_id: int,
    role: str,
    user=Depends(require_admin)
):
    role = role.strip().lower()

    allowed = {
        "admin",
        "analyst",
        "viewer",
        "customer",
        "executive"
    }

    if role not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid role."
        )

    if user.get("id") == user_id and role != "admin":
        raise HTTPException(
            status_code=400,
            detail="An administrator cannot remove their own administrator role."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                UPDATE users
                SET role = ?,
                    session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (role, user_id)
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        conn.commit()

        return {
            "success": True,
            "user_id": user_id,
            "role": role
        }

    finally:
        conn.close()


@app.patch("/admin/users/{user_id}/tenant")
def admin_change_user_tenant(
    user_id: int,
    tenant_id: str,
    user=Depends(require_admin)
):
    tenant_id = tenant_id.strip()

    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="Tenant ID is required."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                UPDATE users
                SET tenant_id = ?,
                    session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (tenant_id, user_id)
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        conn.commit()

        return {
            "success": True,
            "user_id": user_id,
            "tenant_id": tenant_id
        }

    finally:
        conn.close()


@app.post("/admin/users/{user_id}/password-reset")
def admin_password_reset(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT id, username, email
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        reset_token = secrets.token_urlsafe(48)
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        cursor.execute(
            db_sql("""
                UPDATE users
                SET reset_token = ?,
                    reset_token_expires = ?,
                    password_reset_required = 1
                WHERE id = ?
            """),
            (
                reset_token,
                expires_at.isoformat(),
                user_id
            )
        )

        conn.commit()

        try:
            create_audit_log(
                action="ADMIN_PASSWORD_RESET",
                user=user.get("username"),
                message=f"Password reset initiated for {target['username']}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "message": "Password reset token generated.",
            "username": target["username"],
            "expires_at": expires_at.isoformat(),
            "reset_token": reset_token
        }

    finally:
        conn.close()


@app.post("/admin/users/{user_id}/mfa-reset")
def admin_mfa_reset(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                UPDATE users
                SET mfa_enabled = 0,
                    session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (user_id,)
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        conn.commit()

        return {
            "success": True,
            "message": "MFA has been reset and existing sessions revoked."
        }

    finally:
        conn.close()


@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    user=Depends(require_admin)
):
    if user.get("id") == user_id:
        raise HTTPException(
            status_code=400,
            detail="An administrator cannot delete their own account."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT username
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        cursor.execute(
            db_sql("""
                DELETE FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        conn.commit()

        try:
            create_audit_log(
                action="USER_DELETED",
                user=user.get("username"),
                message=f"Admin deleted user {target['username']}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "message": "User account deleted."
        }

    finally:
        conn.close()


@app.get("/executive-ai")
def executive_ai():

    summary = executive_summary()

    graph = {
        "nodes": list(ATTACK_GRAPH["nodes"].values()),
        "edges": ATTACK_GRAPH["edges"]
    }

    nodes = graph.get("nodes", [])


    # fallback to incidents when attack graph is empty
    if len(nodes) == 0:

        incidents = get_incidents()

        nodes = []

        for i in incidents:

            category = i.get("category", "Unknown")

            if category == "Safe":
                continue

            nodes.append({
                "id": i.get("id"),
                "category": category,
                "max_score": (
                    i.get("risk_score")
                    or i.get("score")
                    or 0
                )
            })

        graph["nodes"] = nodes


    scores = []

    for n in nodes:

        score = (
            n.get("max_score")
            or n.get("score")
            or n.get("risk_score")
            or 0
        )

        try:
            score = int(score)
        except:
            score = 0

        scores.append(score)


    critical = summary.get(
    "critical_threats",
    0
)

    high = summary.get(
    "open_incidents",
    0
)


    probability = min(
    100,
    (critical * 20) + (min(high, 20) * 2)
)


    security_score = summary.get(
    "security_score",
    0
)


    if critical > 0:

        severity = "Critical"

        recommendation = (
            "Immediate executive response required. "
            "Contain affected systems and activate incident response."
        )


    elif high > 0:

        severity = "High"

        recommendation = (
            "High-risk threats detected. "
            "SOC investigation required."
        )
    else:

        severity = "Low"

        recommendation = "Environment is stable."

    ai = executive_reasoning(
    summary,
    {
        "nodes": nodes,
        "edges": graph["edges"]
    }
)
    return {
        "severity": severity,
        "probability": probability,
        "critical_nodes": critical,
        "high_nodes": high,
        "security_score": security_score,
        "recommendation": recommendation,
        "summary": summary,

        "executive_summary": ai.get("summary", ""),
        "top_threats": ai.get("top_threats", []),
        "confidence": ai.get("confidence", 0)
    }
@app.get("/executive/incident-commander")
def executive_incident_commander():
    return {
        "total_active": len(ACTIVE_INCIDENTS),
        "incidents": list(ACTIVE_INCIDENTS.values())
    }
@app.post("/executive/close-incident/{incident_id}")
def executive_close_incident(incident_id: int):

    return close_incident(incident_id)
@app.get("/executive/active-count")
def active_count():

    return {
        "active": len(ACTIVE_INCIDENTS)
    }
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": "SafeChat AI SOC",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "database": "connected",
        "api": "running"
    }
@app.get("/executive-ai-brief")
def executive_ai_brief():

    return {
        "overall_risk": "HIGH",
        "executive_summary":
            "Critical phishing activity increased across the enterprise. AI predicts elevated credential theft risk within the next 24 hours.",

        "top_business_risks": [
            "Credential compromise",
            "Financial fraud",
            "Business email compromise",
            "Data exfiltration"
        ],

        "recommended_actions": [
            "Enable MFA enforcement",
            "Block malicious IP addresses",
            "Reset compromised credentials",
            "Patch exposed systems"
        ],

        "predictions": {
            "next_24h": "High",
            "next_7d": "Elevated",
            "confidence": 96
        }
    }
@app.get("/attack-path-analysis")
def attack_path_analysis():

    return {
        "paths": [
            {
                "id": 1,
                "probability": 92,
                "risk": "Critical",
                "business_impact": "High",
                "steps": [
                    "Internet",
                    "Email Gateway",
                    "Employee Laptop",
                    "Domain Controller",
                    "Finance Database"
                ]
            },
            {
                "id": 2,
                "probability": 71,
                "risk": "High",
                "business_impact": "Medium",
                "steps": [
                    "VPN",
                    "Application Server",
                    "SQL Server"
                ]
            }
        ]
    }

@app.get("/executive/recommendations")
def executive_recommendations():

    recommendations = [
        {
            "priority": "Critical",
            "title": "Strengthen Identity Protection",
            "action": "Enable MFA for all privileged accounts."
        },
        {
            "priority": "High",
            "title": "Reduce Attack Surface",
            "action": "Patch internet-facing systems with critical vulnerabilities."
        },
        {
            "priority": "Medium",
            "title": "Improve Threat Detection",
            "action": "Tune SIEM correlation rules and review alert thresholds."
        }
    ]

    return {
        "generated": datetime.utcnow().isoformat(),
        "recommendations": recommendations
    }
def build_mitre_matrix():
    data = soc_metrics()

    total = max(data["total_scans"], 1)
    critical = data["critical_threats"]

    return {
        "Initial Access": min(100, round(total * 0.18)),
        "Execution": min(100, round(total * 0.22)),
        "Persistence": min(100, round(total * 0.15)),
        "Privilege Escalation": min(100, round(critical * 0.35)),
        "Defense Evasion": min(100, round(total * 0.17)),
        "Credential Access": min(100, round(critical * 0.45)),
        "Discovery": min(100, round(total * 0.25)),
        "Lateral Movement": min(100, round(critical * 0.30)),
        "Collection": min(100, round(total * 0.14)),
        "Exfiltration": min(100, round(critical * 0.20))
    }
def build_enterprise_digital_twin():

    return {
        "Internet": 28,
        "Firewall": 12,
        "Email Gateway": 33,
        "Identity": 24,
        "Enterprise Servers": 41,
        "Databases": 18,
        "Finance": 9,
        "attack_paths": len(ATTACK_GRAPH["edges"]),
        "protected_assets": build_security_posture()["protected_assets"]
    }

# ==============================
# EXECUTIVE WAR ROOM ACTIONS
# ==============================

CRISIS_MODE = False
EXECUTIVE_STATUS = {
    "posture": "NORMAL",
    "risk_level": "LOW",
    "reason": "No active incidents",
    "updated": datetime.utcnow().isoformat()
}


def update_executive_posture(
    posture,
    risk_level,
    reason
):

    EXECUTIVE_STATUS.update({

        "posture": posture,
        "risk_level": risk_level,
        "reason": reason,
        "updated": datetime.utcnow().isoformat()

    })


    return EXECUTIVE_STATUS

EXECUTIVE_EVENTS = []


def add_executive_event(event_type, message, severity="INFO"):

    event = {
        "type": event_type,
        "message": message,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat()
    }

    EXECUTIVE_EVENTS.insert(0, event)

    if len(EXECUTIVE_EVENTS) > 100:
        EXECUTIVE_EVENTS.pop()

    return event

@app.post("/executive/declare-incident")
async def declare_incident():

    update_executive_posture(
        "INCIDENT RESPONSE",
        "CRITICAL",
        "Executive incident declared"
    )


    event = add_executive_event(
        "INCIDENT",
        "ÃƒÂ°Ã…Â¸Ã…Â¡Ã‚Â¨ Incident declared by Executive Commander",
        "CRITICAL"
    )


    await manager.broadcast(event)


    return {
        "status":"success",
        "message":"Incident declared",
        "posture": EXECUTIVE_STATUS
    }

@app.post("/executive/crisis-mode")
async def crisis_mode():

    global CRISIS_MODE

    CRISIS_MODE = True


    update_executive_posture(
        "CRISIS",
        "CRITICAL",
        "Enterprise crisis mode activated"
    )


    event = add_executive_event(
        "CRISIS",
        "ÃƒÂ¢Ã…Â¡Ã‚Â  Enterprise crisis mode activated",
        "CRITICAL"
    )


    await manager.broadcast(event)


    return {
        "success":True,
        "message":"ÃƒÂ¢Ã…Â¡Ã‚Â  Executive Crisis Mode Activated",
        "posture": EXECUTIVE_STATUS
    }

@app.post("/executive/notify-board")
async def notify_board():

    event = add_executive_event(
        "BOARD",
        "ÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã‚Â¢ Board members notified",
        "HIGH"
    )

    await manager.broadcast(event)


    return {
        "success": True,
        "message": "ÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã‚Â¢ Board Members Notified",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/executive/generate-report")
async def generate_report():

    summary = executive_summary()
    decision = executive_ai_decision()


    report = {

        "generated":
            datetime.utcnow().isoformat(),

        "security_score":
            summary.get("security_score"),

        "critical_threats":
            summary.get("critical_threats"),

        "enterprise_risk":
            decision.get("enterprise_risk"),

        "recommendation":
            decision.get("recommendation")
    }


    event = add_executive_event(
        "REPORT",
        "ÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã¢â‚¬Å¾ Executive security report generated",
        "INFO"
    )

    await manager.broadcast(event)


    return {
        "success": True,
        "message": "ÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã¢â‚¬Å¾ Executive Report Generated",
        "report": report
    }

@app.get("/executive/live-events")
async def executive_live_events():

    return {
        "events": EXECUTIVE_EVENTS
    }
@app.get("/executive/posture")
async def executive_posture():

    return EXECUTIVE_STATUS
@app.get("/attack-replay")
def attack_replay():

    return get_replay()









