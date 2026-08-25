import json
import uuid
from datetime import datetime, timezone

from db import get_conn, db_sql


def utc_now():
    return datetime.now(timezone.utc)


def safe_text(value):
    if value is None:
        return None

    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)

    return str(value)


def normalize_event(payload: dict) -> dict:
    now = utc_now()

    risk = payload.get("risk_score", payload.get("score", 0))
    confidence = payload.get("confidence", 0)

    try:
        risk = float(risk or 0)
    except (TypeError, ValueError):
        risk = 0.0

    try:
        confidence = float(confidence or 0)
    except (TypeError, ValueError):
        confidence = 0.0

    if confidence > 1:
        confidence = confidence / 100.0

    return {
        "event_id": safe_text(
            payload.get("event_id") or uuid.uuid4()
        ),
        "tenant_id": safe_text(
            payload.get("tenant_id") or "demo"
        ),
        "timestamp": safe_text(
            payload.get("timestamp") or now.isoformat()
        ),

        "source": safe_text(
            payload.get("source") or "unknown"
        ),
        "event_type": safe_text(
            payload.get("event_type") or "security_event"
        ),

        "actor": safe_text(payload.get("actor")),
        "user": safe_text(payload.get("user")),
        "device": safe_text(payload.get("device")),
        "hostname": safe_text(payload.get("hostname")),
        "application": safe_text(payload.get("application")),

        "ip": safe_text(payload.get("ip")),
        "domain": safe_text(payload.get("domain")),
        "url": safe_text(payload.get("url")),
        "ioc": safe_text(payload.get("ioc")),

        "threat_category": safe_text(
            payload.get("threat_category", payload.get("category"))
        ),

        "mitre_technique": safe_text(
            payload.get("mitre_technique", payload.get("mitre"))
        ),

        "campaign_id": safe_text(
            payload.get("campaign_id")
        ),

        "risk_score": risk,
        "confidence": confidence,

        "severity": safe_text(
            payload.get("severity") or "UNKNOWN"
        ),

        "status": safe_text(
            payload.get("status") or "OPEN"
        ),

        "correlation_id": safe_text(
            payload.get("correlation_id")
            or payload.get("corr_id")
            or uuid.uuid4()
        ),

        "evidence": json.dumps(
            payload.get("evidence", {}),
            default=str
        ),

        "raw_event": json.dumps(
            payload,
            default=str
        ),
    }


def init_security_fabric():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            timestamp TEXT NOT NULL,

            source TEXT,
            event_type TEXT,

            actor TEXT,
            "user" TEXT,
            device TEXT,
            hostname TEXT,
            application TEXT,

            ip TEXT,
            domain TEXT,
            url TEXT,
            ioc TEXT,

            threat_category TEXT,
            mitre_technique TEXT,
            campaign_id TEXT,

            risk_score DOUBLE PRECISION DEFAULT 0,
            confidence DOUBLE PRECISION DEFAULT 0,

            severity TEXT,
            status TEXT,

            correlation_id TEXT,

            evidence TEXT,
            raw_event TEXT
        )
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_security_events_tenant
        ON security_events(tenant_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
        ON security_events(timestamp)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_security_events_correlation
        ON security_events(correlation_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_security_events_campaign
        ON security_events(campaign_id)
    """))

    conn.commit()
    conn.close()


def persist_security_event(payload: dict) -> dict:
    event = normalize_event(payload)

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            INSERT INTO security_events (
                event_id,
                tenant_id,
                timestamp,
                source,
                event_type,
                actor,
                "user",
                device,
                hostname,
                application,
                ip,
                domain,
                url,
                ioc,
                threat_category,
                mitre_technique,
                campaign_id,
                risk_score,
                confidence,
                severity,
                status,
                correlation_id,
                evidence,
                raw_event
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            ON CONFLICT (event_id) DO NOTHING
        """),
        (
            event["event_id"],
            event["tenant_id"],
            event["timestamp"],
            event["source"],
            event["event_type"],
            event["actor"],
            event["user"],
            event["device"],
            event["hostname"],
            event["application"],
            event["ip"],
            event["domain"],
            event["url"],
            event["ioc"],
            event["threat_category"],
            event["mitre_technique"],
            event["campaign_id"],
            event["risk_score"],
            event["confidence"],
            event["severity"],
            event["status"],
            event["correlation_id"],
            event["evidence"],
            event["raw_event"],
        )
    )

    conn.commit()
    conn.close()

    return event



def get_security_event(event_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM security_events
            WHERE event_id = ?
            LIMIT 1
        """),
        (event_id,)
    )

    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    return dict(row)



def get_security_events(limit=100, tenant_id=None):
    conn = get_conn()
    cur = conn.cursor()

    if tenant_id:
        cur.execute(
            db_sql("""
                SELECT *
                FROM security_events
                WHERE tenant_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """),
            (tenant_id, limit)
        )
    else:
        cur.execute(
            db_sql("""
                SELECT *
                FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            """),
            (limit,)
        )

    rows = cur.fetchall()
    conn.close()

    return [dict(row) for row in rows]
