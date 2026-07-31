import sqlite3
import threading
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(os.path.dirname(__file__), "scams.db")

def init_db():
    conn = sqlite3.connect(DB_NAME)
lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")

    return conn


    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        category TEXT,
        risk_score INTEGER,
        status TEXT,
        user TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        message TEXT,
        category TEXT,
        severity TEXT,
        status TEXT DEFAULT 'OPEN',
        assigned_to TEXT,
        priority INTEGER DEFAULT 1,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP
    )
    """)

    cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    level TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        user TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_intelligence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT,
        threat_count INTEGER DEFAULT 0,
        confidence REAL,
        trend TEXT,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
def insert_scan(message, category, score, status, user):
    with lock:
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO scans (
            message,
            category,
            risk_score,
            status,
            user
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            message,
            category,
            score,
            status,
            user
        ))

        conn.commit()
        conn.close()


def fetch_all():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()

    conn.close()
    return rows


def fetch_recent(limit=10):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
        (limit,)
    )

    rows = cursor.fetchall()

    conn.close()
    return rows


def fetch_user_scans(user):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        WHERE user = ?
        ORDER BY id DESC
    """, (user,))

    rows = cursor.fetchall()

    conn.close()
    return rows


def create_incident(scan_id, message, category, severity, assigned_to="SOC Analyst"):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incidents (
            scan_id,
            message,
            category,
            severity,
            status,
            assigned_to,
            priority
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        message,
        category,
        severity,
        "OPEN",
        assigned_to,
        1
    ))

    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()

    return incident_id
def update_incident_status(incident_id, status, notes=None):

    conn = get_conn()
    cursor = conn.cursor()

    if notes:
        cursor.execute("""
            UPDATE incidents
            SET status = ?, notes = ?
            WHERE id = ?
        """, (status, notes, incident_id))
    else:
        cursor.execute("""
            UPDATE incidents
            SET status = ?
            WHERE id = ?
        """, (status, incident_id))

    conn.commit()
    conn.close()


def create_alert(message, level):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (message, level)
        VALUES (?, ?)
    """, (message, level))

    conn.commit()
    conn.close()
def create_alert(message, level):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM alerts
        WHERE message = ? AND level = ?
        ORDER BY id DESC LIMIT 1
    """, (message, level))

    exists = cursor.fetchone()

    if exists:
        conn.close()
        return

    cursor.execute("""
        INSERT INTO alerts (message, level)
        VALUES (?, ?)
    """, (message, level))

    conn.commit()
    conn.close()


def create_audit_log(action, user):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO audit_logs (
        action,
        user
    )
    VALUES (?, ?)
    """, (
        action,
        user
    ))

    conn.commit()
    conn.close()
def get_incidents():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM incidents
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]


def get_open_incidents():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM incidents
    WHERE status='OPEN'
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]


def get_alerts():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM alerts
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]


def get_audit_logs():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM audit_logs
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]
def get_total_scans():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]

    conn.close()
    return total


def get_total_alerts():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]

    conn.close()
    return total


def get_total_incidents():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM incidents")
    total = cursor.fetchone()[0]

    conn.close()
    return total


def get_open_incident_count():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM incidents WHERE status='Open'"
    )

    total = cursor.fetchone()[0]

    conn.close()
    return total

def update_threat_intelligence(category, confidence):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, threat_count
    FROM threat_intelligence
    WHERE category = ?
    """, (category,))

    row = cursor.fetchone()

    if row:

        cursor.execute("""
        UPDATE threat_intelligence
        SET threat_count = threat_count + 1,
            confidence = ?,
            last_seen = CURRENT_TIMESTAMP
        WHERE category = ?
        """, (confidence, category))

    else:

        cursor.execute("""
        INSERT INTO threat_intelligence(
            category,
            threat_count,
            confidence,
            trend
        )
        VALUES (?, ?, ?, ?)
        """, (
            category,
            1,
            confidence,
            "New"
        ))

    conn.commit()
    conn.close()
def get_threat_intelligence():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM threat_intelligence
    ORDER BY threat_count DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(r) for r in rows]
def update_threat_trends():
    with lock:
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT category, threat_count, last_seen
            FROM threat_intelligence
        """)

        rows = cursor.fetchall()

        for r in rows:
            category = r["category"]

            cursor.execute("""
                SELECT threat_count
                FROM threat_intelligence
                WHERE category = ?
                ORDER BY last_seen DESC
                LIMIT 2
            """, (category,))

            history = cursor.fetchall()

            if len(history) >= 2:
                latest = history[0]["threat_count"]
                previous = history[1]["threat_count"]

                if latest > previous:
                    trend = "Rising"
                elif latest < previous:
                    trend = "Falling"
                else:
                    trend = "Stable"
            else:
                trend = "New"

            cursor.execute("""
                UPDATE threat_intelligence
                SET trend = ?
                WHERE category = ?
            """, (trend, category))

        conn.commit()
        conn.close()
def calculate_risk_score(category, base_score):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT threat_count
        FROM threat_intelligence
        WHERE category = ?
    """, (category,))

    row = cursor.fetchone()

    threat_count = row["threat_count"] if row else 0

    risk_score = (base_score * 0.6) + (threat_count * 3)

    if risk_score > 80:
        level = "Critical"
    elif risk_score > 50:
        level = "High Risk"
    elif risk_score > 25:
        level = "Suspicious"
    else:
        level = "Low Risk"

    conn.close()

    # 🔥 ALWAYS RETURN (this is what you were missing in crash cases)
    return {
        "risk_score": round(risk_score, 2),
        "level": level
    }
# =========================
# ANALYTICS
# =========================

def get_category_distribution():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT category, COUNT(*) as total
        FROM scans
        GROUP BY category
        ORDER BY total DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]


def get_executive_kpis():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents")
    incidents = cursor.fetchone()[0]

    conn.close()

    return {
        "total_scans": scans,
        "total_alerts": alerts,
        "total_incidents": incidents
    }

    if risk_score > 80:
        level = "Critical"
    elif risk_score > 50:
        level = "High Risk"
    elif risk_score > 25:
        level = "Suspicious"
    else:
        level = "Low Risk"

    return {
        "risk_score": round(risk_score, 2),
        "level": level
    }


    valid_states = ["OPEN", "INVESTIGATING", "ESCALATED", "RESOLVED", "CLOSED"]

    if status not in valid_states:
        return {"error": "Invalid status"}

    conn = get_conn()
    cursor = conn.cursor()

    if notes:
        cursor.execute("""
            UPDATE incidents
            SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (status, notes, incident_id))
    else:
        cursor.execute("""
            UPDATE incidents
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (status, incident_id))

    conn.commit()
    conn.close()

    return {"status": "updated"}