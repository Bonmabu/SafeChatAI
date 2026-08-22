import os
from dotenv import load_dotenv
import psycopg
from psycopg.rows import dict_row

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_URL = os.getenv("DATABASE_URL")

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "SafeChatAI.db")
)


def get_conn():
    if DATABASE_URL:
        return psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row
        )

    import sqlite3

    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn



def db_sql(sql):
    """Use SQLite ? placeholders locally and PostgreSQL %s placeholders when DATABASE_URL is set."""
    if DATABASE_URL:
        return sql.replace("?", "%s")
    return sql


def db_date(column):
    """Return portable SQL expression for extracting a date."""
    if DATABASE_URL:
        return f"DATE({column})"
    return f"DATE({column})"


def db_week(column):
    """Return portable SQL expression for year-week grouping."""
    if DATABASE_URL:
        return f"TO_CHAR({column}, 'IYYY-IW')"
    return f"strftime('%Y-%W', {column})"


def db_age_days(column):
    """Return portable SQL expression for age in days."""
    if DATABASE_URL:
        return f"EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - {column})) / 86400.0"
    return f"julianday('now') - julianday({column})"


def db_recent_hours(column, hours):
    """Return portable SQL expression for recent-hour filtering."""
    if DATABASE_URL:
        return f"{column} >= CURRENT_TIMESTAMP - INTERVAL '{hours} hours'"
    return f"datetime({column}) >= datetime('now', '-{hours} hour')"


def init_db():

    conn = get_conn()
    cursor = conn.cursor()

    if DATABASE_URL:

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id BIGSERIAL PRIMARY KEY,
            message TEXT,
            category TEXT,
            risk_score DOUBLE PRECISION,
            status TEXT,
            "user" TEXT,
            tenant_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id BIGSERIAL PRIMARY KEY,
            message TEXT,
            level TEXT,
            tenant_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id BIGSERIAL PRIMARY KEY,
            tenant_id TEXT UNIQUE,
            company_name TEXT,
            industry TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'customer',
            tenant_id TEXT NOT NULL,
            reset_token TEXT,
            reset_token_expires TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_iocs (
            id BIGSERIAL PRIMARY KEY,
            ioc TEXT UNIQUE,
            ioc_type TEXT,
            reputation TEXT,
            risk_score INTEGER,
            sources TEXT,
            first_seen TEXT,
            last_seen TEXT,
            sightings INTEGER DEFAULT 1
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id BIGSERIAL PRIMARY KEY,
            scan_id BIGINT,
            tenant_id TEXT,
            message TEXT,
            category TEXT,
            threat_type TEXT,
            risk_score DOUBLE PRECISION DEFAULT 0,
            severity TEXT,
            priority TEXT DEFAULT 'MEDIUM',
            stage TEXT DEFAULT 'UNKNOWN',
            mitre TEXT DEFAULT 'TA0000 - Unknown',
            status TEXT DEFAULT 'OPEN',
            assigned_to TEXT,
            notes TEXT,
            threat_intel TEXT,
            correlation_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id BIGSERIAL PRIMARY KEY,
            action TEXT,
            "user" TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id BIGSERIAL PRIMARY KEY,
            tenant_id TEXT DEFAULT 'demo',
            indicator TEXT UNIQUE,
            category TEXT,
            score DOUBLE PRECISION DEFAULT 0,
            sightings INTEGER DEFAULT 1,
            confidence DOUBLE PRECISION DEFAULT 50,
            campaign TEXT,
            trend TEXT DEFAULT 'NEW',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_hunts (
            id BIGSERIAL PRIMARY KEY,
            timestamp TEXT,
            analyst TEXT,
            category TEXT,
            severity TEXT,
            keyword TEXT,
            result_count INTEGER,
            risk TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_dna (
            id BIGSERIAL PRIMARY KEY,
            fingerprint TEXT UNIQUE NOT NULL,
            category TEXT,
            risk_band TEXT,
            mitre TEXT,
            behavior_signature TEXT,
            urls INTEGER DEFAULT 0,
            emails INTEGER DEFAULT 0,
            ips INTEGER DEFAULT 0,
            score DOUBLE PRECISION DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            occurrences INTEGER DEFAULT 0
        )
        """)

    else:

        import sqlite3

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            category TEXT,
            risk_score REAL,
            status TEXT,
            user TEXT,
            tenant_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            level TEXT,
            tenant_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT UNIQUE,
            company_name TEXT,
            industry TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'customer',
            tenant_id TEXT NOT NULL,
            reset_token TEXT,
            reset_token_expires TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc TEXT UNIQUE,
            ioc_type TEXT,
            reputation TEXT,
            risk_score INTEGER,
            sources TEXT,
            first_seen TEXT,
            last_seen TEXT,
            sightings INTEGER DEFAULT 1
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            tenant_id TEXT,
            message TEXT,
            category TEXT,
            threat_type TEXT,
            risk_score REAL DEFAULT 0,
            severity TEXT,
            priority TEXT DEFAULT 'MEDIUM',
            stage TEXT DEFAULT 'UNKNOWN',
            mitre TEXT DEFAULT 'TA0000 - Unknown',
            status TEXT DEFAULT 'OPEN',
            assigned_to TEXT,
            notes TEXT,
            threat_intel TEXT,
            correlation_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            user TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT DEFAULT 'demo',
            indicator TEXT UNIQUE,
            category TEXT,
            score REAL DEFAULT 0,
            sightings INTEGER DEFAULT 1,
            confidence REAL DEFAULT 50,
            campaign TEXT,
            trend TEXT DEFAULT 'NEW',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_hunts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            analyst TEXT,
            category TEXT,
            severity TEXT,
            keyword TEXT,
            result_count INTEGER,
            risk TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_dna (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT UNIQUE NOT NULL,
            category TEXT,
            risk_band TEXT,
            mitre TEXT,
            behavior_signature TEXT,
            urls INTEGER DEFAULT 0,
            emails INTEGER DEFAULT 0,
            ips INTEGER DEFAULT 0,
            score REAL DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            occurrences INTEGER DEFAULT 0
        )
        """)

    conn.commit()
    conn.close()


def calculate_risk_score(category, base_score):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(db_sql("""
        SELECT COUNT(*) AS sightings
        FROM threat_intelligence
        WHERE category = ?
    """), (category,))

    row = cur.fetchone()
    conn.close()

    sightings = row["sightings"] if row else 0

    risk = float(base_score) + sightings * 2
    risk = max(0, min(risk, 100))

    if risk >= 80:
        level = "High Risk"
    elif risk >= 50:
        level = "Suspicious"
    else:
        level = "Low Risk"

    return {
        "risk_score": round(risk, 2),
        "level": level
    }
def update_threat_intelligence(category, confidence):
    return upsert_threat_intelligence(
        indicator=category,
        category=category,
        score=confidence
    )
def get_threat_intelligence():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            indicator,
            category,
            score,
            sightings,
            confidence,
            campaign,
            first_seen,
            last_seen
        FROM threat_intelligence
        ORDER BY confidence DESC, sightings DESC
    """)

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
def create_alert(message, level, tenant_id="demo"):
    conn = get_conn()
    cursor = conn.cursor()

    # prevent duplicates
    cursor.execute(db_sql("""
        SELECT id FROM alerts
        WHERE message = ? AND level = ?
        ORDER BY id DESC LIMIT 1
    """), (message, level))

    exists = cursor.fetchone()

    if exists:
        conn.close()
        return

    cursor.execute(db_sql("""
    INSERT INTO alerts (
        message,
        level,
        tenant_id
    )
    VALUES (?, ?, ?)
"""), (
    message,
    level,
    tenant_id
))

    conn.commit()
    conn.close()
def create_audit_log(action=None, user=None, message=None):
    conn = get_conn()
    cursor = conn.cursor()

    # normalize inputs (VERY IMPORTANT FIX)
    if message and not action:
        action = message

    cursor.execute(db_sql("""
        INSERT INTO audit_logs (action, user, message)
        VALUES (?, ?, ?)
    """), (action, user, message))

    conn.commit()
    conn.close()
def create_incident(
    scan_id=None,
    tenant_id="demo",
    message="",
    category="Unknown",
    threat_type="Unknown",
    risk_score=0,
    stage="UNKNOWN",
    mitre="TA0000 - Unknown",
    status="OPEN",
    severity="Medium",
    priority="MEDIUM",
    assigned_to=None,
    notes=None,
    threat_intel=None,
    intel=None,
    correlation_id=None
):
    # Always open the database
    conn = get_conn()
    cursor = conn.cursor()

    # Backward compatibility
    if threat_intel is None:
        threat_intel = intel

    cursor.execute(db_sql("""
        INSERT INTO incidents
        (
            scan_id,
            tenant_id,
            message,
            category,
            threat_type,
            risk_score,
            stage,
            mitre,
            status,
            severity,
            priority,
            assigned_to,
            notes,
            threat_intel,
            correlation_id
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """),
    (
        scan_id,
        tenant_id,
        message,
        category,
        threat_type,
        risk_score,
        stage,
        mitre,
        status,
        severity,
        priority,
        assigned_to,
        notes,
        threat_intel,
        correlation_id
    ))

    cursor.execute(db_sql("""
    SELECT id
    FROM incidents
    WHERE correlation_id = ?
    ORDER BY id DESC
    LIMIT 1
"""), (correlation_id,))

    row = cursor.fetchone()
    incident_id = row["id"] if row else None

    conn.commit()
    conn.close()

    return incident_id
def get_executive_kpis():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM scans
    """)
    total_scans = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
    """)
    total_alerts = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
    """)
    total_incidents = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
        WHERE status='OPEN'
    """)
    open_incidents = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT AVG(risk_score) AS average
        FROM scans
    """)
    avg_risk = cursor.fetchone()["average"] or 0

    security_score = round(max(0, 100 - avg_risk), 2)
    enterprise_risk = round(avg_risk, 2)

    cursor.execute("""
        SELECT category, COUNT(*) AS total
        FROM scans
        GROUP BY category
        ORDER BY total DESC
        LIMIT 1
    """)

    row = cursor.fetchone()
    top_threat = row["category"] if row else "None"

    conn.close()

    return {
        "security_score": security_score,
        "enterprise_risk": enterprise_risk,
        "total_scans": total_scans,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "average_risk": round(avg_risk, 2),
        "top_threat": top_threat
    }
def get_incidents(tenant_id="demo"):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(db_sql("""
SELECT
    incidents.id,
    incidents.scan_id,
    incidents.message,
    incidents.category,
    incidents.severity,
    incidents.priority,
    incidents.status,
    incidents.assigned_to,
    incidents.notes,
    incidents.tenant_id,
    incidents.created_at,
    incidents.correlation_id,

    scans.risk_score,
    scans.user

FROM incidents

LEFT JOIN scans
ON incidents.scan_id = scans.id

WHERE incidents.tenant_id = ?

ORDER BY incidents.id DESC
"""), (tenant_id,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
def get_audit_logs():
    return []

def get_total_scans():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM scans
    """)
    total = cur.fetchone()["total"]

    conn.close()
    return total


def get_total_alerts():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
    """)
    total = cur.fetchone()["total"]

    conn.close()
    return total


def get_total_incidents():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
    """)
    total = cur.fetchone()["total"]

    conn.close()
    return total


def get_open_incident_count():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
        WHERE status = 'OPEN'
    """)
    total = cursor.fetchone()["total"]

    conn.close()
    return total
def update_threat_trends():
    pass

def update_incident_status(
    incident_id,
    status,
    notes=None
):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(db_sql("""
        UPDATE incidents
        SET
            status = ?,
            notes = ?
        WHERE id = ?
    """), (
        status,
        notes,
        incident_id
    ))

    conn.commit()

    updated = cur.rowcount

    conn.close()

    return {
        "updated": updated,
        "incident_id": incident_id,
        "status": status
    }
def assign_incident(incident_id, analyst):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(db_sql("""
        UPDATE incidents
        SET assigned_to = ?
        WHERE id = ?
    """), (analyst, incident_id))

    conn.commit()

    updated = cur.rowcount

    conn.close()

    return {
        "updated": updated,
        "incident_id": incident_id,
        "assigned_to": analyst
    }
def get_threat_trends():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT category, COUNT(*) as count, AVG(risk_score) as avg_score
FROM scans
GROUP BY category
ORDER BY count DESC
    """)

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
def get_risk_score():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT AVG(risk_score) AS average
    FROM scans
""")

    row = cur.fetchone()["average"]

    conn.close()

    avg_risk = float(row) if row is not None else 0
    avg_risk = round(avg_risk, 2)

    if avg_risk >= 80:
        level = "CRITICAL"
    elif avg_risk >= 50:
        level = "ELEVATED"
    else:
        level = "LOW"

    return {
        "risk_score": avg_risk,
        "level": level
    }
def get_executive_summary():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM scans
    """)
    total_scans = cur.fetchone()["total"]

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM scans
        WHERE status IN ('High Risk', 'Critical')
    """)
    critical_threats = cur.fetchone()["total"]

    cur.execute("""
        SELECT AVG(risk_score) AS average
        FROM scans
    """)
    avg_risk = cur.fetchone()["average"] or 0

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
    """)
    total_incidents = cur.fetchone()["total"]

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
        WHERE status = 'RESOLVED'
    """)
    resolved = cur.fetchone()["total"]

    conn.close()

    avg_risk = round(float(avg_risk), 2)

    resolution_rate = 0

    if total_incidents > 0:
        resolution_rate = round(
            (resolved / total_incidents) * 100,
            2
        )

    return {
        "total_scans": total_scans,
        "critical_threats": critical_threats,
        "average_risk": avg_risk,
        "resolution_rate": resolution_rate
    }
def get_top_threat():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT category, COUNT(*) as count
        FROM scans
        GROUP BY category
        ORDER BY count DESC
        LIMIT 1
    """)

    row = cur.fetchone()
    conn.close()

    if row:
        return dict(row)

    return {
        "category": "None",
        "count": 0
    }
def get_daily_threats():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(f"""
        SELECT {db_date("created_at")} as day,
               COUNT(*) as total
        FROM scans
        GROUP BY {db_date("created_at")}
        ORDER BY day DESC
        LIMIT 30
    """)

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
def get_weekly_threats():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(f"""
        SELECT {db_week("created_at")} as week,
               COUNT(*) as total
        FROM scans
        GROUP BY week
        ORDER BY week DESC
    """)

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
def get_risk_heatmap():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            category,
            ROUND(AVG(risk_score),2) as risk
        FROM scans
        GROUP BY category
        ORDER BY risk DESC
    """)

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]
def get_incident_lifecycle_metrics():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(f"""
        SELECT
            status,
            {db_age_days("created_at")} as age_days
        FROM incidents
    """)

    rows = cur.fetchall()
    conn.close()

    open_0_1 = 0
    open_1_3 = 0
    open_3_plus = 0

    for r in rows:
        if r["status"] == "OPEN":
            age = r["age_days"]

            if age <= 1:
                open_0_1 += 1
            elif age <= 3:
                open_1_3 += 1
            else:
                open_3_plus += 1

    return {
        "open_0_1_day": open_0_1,
        "open_1_3_days": open_1_3,
        "open_3_plus_days": open_3_plus
    }

import datetime

def get_threat_velocity():
    conn = get_conn()
    cur = conn.cursor()

    # last 1 hour data
    cur.execute(f"""
        SELECT created_at
        FROM scans
        WHERE {db_recent_hours("created_at", 1)}
    """)

    rows = cur.fetchall()
    conn.close()

    total = len(rows)

    # per minute rate
    velocity = total / 60

    # classify burst level
    if velocity > 5:
        status = "UNDER ATTACK"
    elif velocity > 2:
        status = "ELEVATED"
    else:
        status = "NORMAL"

    return {
        "threats_last_hour": total,
        "threats_per_minute": round(velocity, 2),
        "status": status
    }
def get_threat_anomaly_score():
    conn = get_conn()
    cur = conn.cursor()

    # last 1 hour
    cur.execute(f"""
    SELECT COUNT(*) AS total
    FROM scans
    WHERE {db_recent_hours("created_at", 1)}
""")
    last_hour = cur.fetchone()["total"]

    # last 24 hours baseline
    cur.execute(f"""
        SELECT COUNT(*) AS total
        FROM scans
        WHERE {db_recent_hours("created_at", 24)}
    """)
    last_24h = cur.fetchone()["total"]

    conn.close()

    # avoid division errors
    baseline = last_24h / 24 if last_24h > 0 else 1

    deviation = (last_hour - baseline) / baseline * 100

    # classification
    if deviation > 200:
        level = "CRITICAL ANOMALY"
    elif deviation > 100:
        level = "HIGH ANOMALY"
    elif deviation > 50:
        level = "MODERATE ANOMALY"
    else:
        level = "NORMAL"

    return {
        "last_hour": last_hour,
        "baseline_per_hour": round(baseline, 2),
        "deviation_percent": round(deviation, 2),
        "anomaly_level": level
    }
def get_soc_intelligence_core():
    conn = get_conn()
    cur = conn.cursor()

    # --------------------------
    # 1. Risk score baseline
    # --------------------------
    cur.execute("SELECT risk_score FROM scans")
    risks = [r["risk_score"] for r in cur.fetchall()]

    avg_risk = sum(risks) / len(risks) if risks else 0

    # --------------------------
    # 2. Critical threats
    # --------------------------
    cur.execute("""
    SELECT COUNT(*) AS total
    FROM scans
    WHERE status IN ('High Risk', 'Critical')
""")
    critical = cur.fetchone()["total"]

    # --------------------------
    # 3. Velocity (last 1 hour)
    # --------------------------
    cur.execute(f"""
    SELECT COUNT(*) AS total
    FROM scans
    WHERE {db_recent_hours("created_at", 1)}
""")
    velocity = cur.fetchone()["total"]

    # --------------------------
    # 4. Anomaly (last 1 hour vs baseline)
    # --------------------------
    cur.execute(f"""
    SELECT COUNT(*) AS total
    FROM scans
    WHERE {db_recent_hours("created_at", 24)}
""")
    last_24h = cur.fetchone()["total"]

    conn.close()

    baseline = last_24h / 24 if last_24h else 1
    anomaly = ((velocity - baseline) / baseline) * 100

    # --------------------------
    # 5. SOC SCORE FORMULA
    # --------------------------

    score = 100

    # risk penalty
    score -= avg_risk * 0.4

    # critical threat penalty
    score -= critical * 5

    # velocity penalty
    if velocity > 10:
        score -= 20
    elif velocity > 5:
        score -= 10

    # anomaly penalty
    if anomaly > 200:
        score -= 30
    elif anomaly > 100:
        score -= 20
    elif anomaly > 50:
        score -= 10

    # clamp
    score = max(0, min(100, score))

    # status classification
    if score >= 80:
        status = "HEALTHY"
    elif score >= 50:
        status = "WARNING"
    else:
        status = "CRITICAL"

    return {
        "soc_score": round(score, 2),
        "status": status,
        "avg_risk": round(avg_risk, 2),
        "critical_threats": critical,
        "velocity": velocity,
        "anomaly": round(anomaly, 2)
    }
def generate_incident_response(category, risk_score, status):
    actions = []

    # High severity logic
    if risk_score >= 80 or status == "High Risk":
        actions.append("IMMEDIATE ISOLATION RECOMMENDED")
        actions.append("Escalate to SOC Level 2")
        actions.append("Block source IP / user session")

    # Medium severity
    elif risk_score >= 50:
        actions.append("Monitor closely for 30 minutes")
        actions.append("Flag for analyst review")
        actions.append("Increase logging level")

    # Low severity
    else:
        actions.append("Log event only")
        actions.append("No immediate action required")

    # Category-based intelligence
    if category == "Phishing":
        actions.append("Notify user security awareness team")

    elif category == "Malware":
        actions.append("Run endpoint scan recommendation")

    elif category == "Fraud":
        actions.append("Check transaction history anomalies")

    elif category == "Account Takeover":
        actions.append("Force password reset")

    elif category == "Harassment":
        actions.append("Apply content moderation review")

    return {
        "category": category,
        "risk_score": risk_score,
        "status": status,
        "recommended_actions": actions
    }
def explain_alert(category, message, risk_score, status):
    explanation = []

    # ---------------------------
    # Risk interpretation
    # ---------------------------
    if risk_score >= 80:
        explanation.append("High confidence malicious activity detected based on pattern intensity.")
    elif risk_score >= 50:
        explanation.append("Suspicious behavior detected with moderate risk indicators.")
    else:
        explanation.append("Low risk activity, likely benign or false positive.")

    # ---------------------------
    # Category logic
    # ---------------------------
    if category == "Phishing":
        explanation.append("Message contains social engineering or credential-related keywords.")

    elif category == "Malware":
        explanation.append("Indicators suggest possible malicious payload or exploit attempt.")

    elif category == "Fraud":
        explanation.append("Financial manipulation or scam-like language detected.")

    elif category == "Account Takeover":
        explanation.append("Login anomaly or unauthorized access pattern detected.")

    elif category == "Harassment":
        explanation.append("Abusive or harmful language detected.")

    elif category == "Spam":
        explanation.append("Repetitive or promotional content detected.")

    # ---------------------------
    # Final SOC-style summary
    # ---------------------------
    summary = f"""
SOC ANALYST SUMMARY:
Category: {category}
Risk Level: {status}
Score: {risk_score}

Interpretation:
- {' '.join(explanation)}
"""

    return {
        "category": category,
        "risk_score": risk_score,
        "status": status,
        "explanation": explanation,
        "summary": summary.strip()
    }
def auto_escalate_incident(incident_id, risk_score, category):
    conn = get_conn()
    cur = conn.cursor()

    risk_score = float(risk_score)

    if risk_score >= 80:
        status = "CRITICAL"
        assigned = "SOC Level 2"
    elif risk_score >= 50:
        status = "HIGH"
        assigned = "SOC Analyst"
    else:
        status = "LOW"
        assigned = "Monitoring"

    cur.execute(db_sql("""
        UPDATE incidents
        SET status = ?,
            assigned_to = ?
        WHERE id = ?
    """), (status, assigned, incident_id))

    if cur.rowcount == 0:
        conn.close()
        return {"error": "Incident not found"}

    conn.commit()
    conn.close()

    return {
        "incident_id": incident_id,
        "status": status,
        "assigned_to": assigned,
        "category": category
    }
def create_scan(
    message,
    category,
    risk_score,
    status,
    user="developer",
    tenant_id="demo"
):
    conn = get_conn()
    cur = conn.cursor()

    if DATABASE_URL:
        cur.execute("""
            INSERT INTO scans (
                message,
                category,
                risk_score,
                status,
                "user",
                tenant_id
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            message,
            category,
            risk_score,
            status,
            "user",
            tenant_id
        ))

        row = cur.fetchone()
        scan_id = row["id"] if row else None

    else:
        cur.execute(db_sql("""
        INSERT INTO scans (
            message,
            category,
            risk_score,
            status,
            "user",
            tenant_id
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """), (
        message,
        category,
        risk_score,
        status,
        user,
        tenant_id
    ))

    cur.execute(db_sql("""
        SELECT id
        FROM scans
        WHERE tenant_id = ?
          AND message = ?
        ORDER BY id DESC
        LIMIT 1
    """), (
        tenant_id,
        message
    ))

    row = cur.fetchone()
    scan_id = row["id"] if row else None

    conn.commit()
    conn.close()

    return scan_id
def save_threat_hunt(
    analyst,
    category,
    severity,
    keyword,
    result_count,
    risk
):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO threat_hunts(
            timestamp,
            analyst,
            category,
            severity,
            keyword,
            result_count,
            risk
        )
        VALUES(CURRENT_TIMESTAMP,
               ?,?,?,?,?,?)
    """, (
        analyst,
        category,
        severity,
        keyword,
        result_count,
        risk
    ))

    conn.commit()
    conn.close()

def upsert_threat_intelligence(indicator, category, score):
    conn = get_conn()
    cur = conn.cursor()

    from datetime import datetime
    now = datetime.now().isoformat()

    cur.execute(db_sql("""
        SELECT sightings
        FROM threat_intelligence
        WHERE indicator=?
    """), (indicator,))

    row = cur.fetchone()

    if row:

        sightings = row["sightings"] + 1
        confidence = min(100, 50 + sightings * 5)

        cur.execute(db_sql("""
            UPDATE threat_intelligence
            SET
                sightings=?,
                confidence=?,
                score=?,
                last_seen=?
            WHERE indicator=?
        """), (
            sightings,
            confidence,
            score,
            now,
            indicator
        ))

    else:

        cur.execute(db_sql("""
            INSERT INTO threat_intelligence(
                indicator,
                category,
                score,
                sightings,
                confidence,
                campaign,
                first_seen,
                last_seen
            )
            VALUES(?,?,?,?,?,?,?,?)
        """), (
            indicator,
            category,
            score,
            1,
            55,
            None,
            now,
            now
        ))

    conn.commit()

    cur.execute(db_sql("""
        SELECT *
        FROM threat_intelligence
        WHERE indicator=?
    """), (indicator,))

    intel = cur.fetchone()

    conn.close()

    return dict(intel) if intel else None
init_db()
def save_threat_ioc(data):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(db_sql("""
    INSERT INTO threat_iocs
    (
        ioc,
        ioc_type,
        reputation,
        risk_score,
        sources,
        first_seen,
        last_seen
    )
    VALUES (?,?,?,?,?,?,?)

    ON CONFLICT(ioc)
    DO UPDATE SET

        reputation=excluded.reputation,
        risk_score=excluded.risk_score,
        last_seen=excluded.last_seen,
        sightings=sightings+1
    """),
    (
        data["ioc"],
        data["type"],
        data["reputation"],
        data["risk_score"],
        str(data["sources"]),
        data["first_seen"],
        data["first_seen"]
    ))

    conn.commit()
    conn.close()
def add_threat_intel_column():
    conn = get_conn()
    cursor = conn.cursor()

    # Add threat_intel to incidents if missing.
    # IF NOT EXISTS works with both SQLite and PostgreSQL.
    try:
        cursor.execute("""
            ALTER TABLE incidents
            ADD COLUMN IF NOT EXISTS threat_intel TEXT
        """)
        print("threat_intel column verified/added to incidents")
    except Exception as e:
        print(f"incidents migration: {e}")

    # Add tenant_id to threat_intelligence if missing.
    try:
        cursor.execute("""
            ALTER TABLE threat_intelligence
            ADD COLUMN IF NOT EXISTS tenant_id TEXT DEFAULT 'demo'
        """)
        print("tenant_id column verified/added to threat_intelligence")
    except Exception as e:
        print(f"threat_intelligence migration: {e}")

    conn.commit()

        
    try:
        cursor.execute(db_sql("""
            SELECT tenant_id
            FROM threat_intelligence
            LIMIT 1
        """))
        print("VERIFIED: threat_intelligence.tenant_id exists")
    except Exception as e:
        print(f"ERROR: threat_intelligence.tenant_id verification failed: {e}")

    conn.close()

def get_category_distribution(tenant_id="demo"):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(db_sql("""
        SELECT category, COUNT(*) as count
        FROM scans
        WHERE tenant_id = ?
        GROUP BY category
    """), (tenant_id,))

    rows = cursor.fetchall()

    conn.close()

    return [
        {
            "category": row["category"],
            "count": row["count"]
        }
        for row in rows
    ]
def save_incident(category, score, status, mitre=None):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(db_sql("""
        INSERT INTO incidents
        (
            category,
            risk_score,
            status,
            mitre
        )
        VALUES (?, ?, ?, ?)
    """), (
        category,
        score,
        status,
        mitre
    ))

    conn.commit()
    conn.close()
def get_executive_threat_map():
    return [
        {
            "country": "Kenya",
            "category": "Malware",
            "risk": 90,
            "count": 14
        },
        {
            "country": "Nigeria",
            "category": "Phishing",
            "risk": 85,
            "count": 11
        },
        {
            "country": "South Africa",
            "category": "Fraud",
            "risk": 80,
            "count": 9
        },
        {
            "country": "United Kingdom",
            "category": "Malware",
            "risk": 75,
            "count": 6
        },
        {
            "country": "United States",
            "category": "Ransomware",
            "risk": 95,
            "count": 5
        }
    ]
def get_executive_risk_forecast():
    return [
        {
            "day": "Today",
            "risk": 41
        },
        {
            "day": "Tomorrow",
            "risk": 45
        },
        {
            "day": "Day 3",
            "risk": 48
        },
        {
            "day": "Day 4",
            "risk": 52
        },
        {
            "day": "Day 5",
            "risk": 49
        },
        {
            "day": "Day 6",
            "risk": 46
        },
        {
            "day": "Day 7",
            "risk": 43
        }
    ]
def create_default_tenant():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(db_sql("""
        INSERT INTO tenants (
            tenant_id,
            company_name,
            industry
        )
        VALUES (?, ?, ?)
        ON CONFLICT (tenant_id) DO NOTHING
    """), (
        "demo",
        "SafeChat AI Demo",
        "Cyber Security"
    ))

    conn.commit()
    conn.close()
init_db()
create_default_tenant()
def save_threat_dna(dna):
    conn = get_conn()
    cursor = conn.cursor()

    fingerprint = dna["fingerprint"]

    cursor.execute(db_sql("""
        SELECT *
        FROM threat_dna
        WHERE fingerprint = ?
    """), (fingerprint,))

    existing = cursor.fetchone()

    ioc_profile = dna.get("ioc_profile", {})

    if existing:
        cursor.execute(db_sql("""
            UPDATE threat_dna
            SET
                category = ?,
                risk_band = ?,
                mitre = ?,
                behavior_signature = ?,
                urls = ?,
                emails = ?,
                ips = ?,
                score = ?,
                last_seen = ?,
                occurrences = occurrences + 1
            WHERE fingerprint = ?
        """), (
            dna["category"],
            dna["risk_band"],
            dna["mitre"],
            dna["behavior_signature"],
            ioc_profile.get("urls", 0),
            ioc_profile.get("emails", 0),
            ioc_profile.get("ips", 0),
            dna["score"],
            dna["timestamp"],
            fingerprint
        ))
    else:
        cursor.execute(db_sql("""
            INSERT INTO threat_dna (
                fingerprint,
                category,
                risk_band,
                mitre,
                behavior_signature,
                urls,
                emails,
                ips,
                score,
                first_seen,
                last_seen,
                occurrences
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """), (
            fingerprint,
            dna["category"],
            dna["risk_band"],
            dna["mitre"],
            dna["behavior_signature"],
            ioc_profile.get("urls", 0),
            ioc_profile.get("emails", 0),
            ioc_profile.get("ips", 0),
            dna["score"],
            dna["timestamp"],
            dna["timestamp"]
        ))

    conn.commit()

    cursor.execute(db_sql("""
        SELECT *
        FROM threat_dna
        WHERE fingerprint = ?
    """), (fingerprint,))

    row = cursor.fetchone()

    conn.close()

    return dict(row) if row else None


def get_all_threat_dna():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM threat_dna
        ORDER BY last_seen DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]

