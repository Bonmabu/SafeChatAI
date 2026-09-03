import hashlib
import json
import uuid
from datetime import datetime, timezone

from db import get_conn, db_sql


CORRELATION_WINDOW_MINUTES = 30
MIN_CORRELATION_SCORE = 0.35


def utc_now():
    return datetime.now(timezone.utc)


def parse_timestamp(value):
    if not value:
        return None

    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt
    except Exception:
        return None


def normalize(value):
    if value is None:
        return ""

    return str(value).strip().lower()


def cluster_id_for(event_ids):
    normalized = sorted(
        str(x) for x in event_ids if x
    )

    digest = hashlib.sha256(
        "|".join(normalized).encode("utf-8")
    ).hexdigest()[:12]

    return f"CLUSTER-{digest.upper()}"


def init_event_correlation():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS event_correlations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            related_event_id TEXT NOT NULL,
            correlation_score DOUBLE PRECISION NOT NULL,
            reasons TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source_event_id, related_event_id)
        )
    """))

    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS correlation_clusters (
            cluster_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            confidence DOUBLE PRECISION DEFAULT 0,
            primary_category TEXT,
            primary_user TEXT,
            primary_device TEXT,
            primary_ip TEXT,
            event_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'ACTIVE',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))

    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS correlation_cluster_members (
            cluster_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            correlation_score DOUBLE PRECISION DEFAULT 0,
            reasons TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(cluster_id, event_id)
        )
    """))


    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS cluster_intelligence (
            cluster_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            risk_score DOUBLE PRECISION DEFAULT 0,
            confidence DOUBLE PRECISION DEFAULT 0,
            severity TEXT DEFAULT 'LOW',
            event_velocity DOUBLE PRECISION DEFAULT 0,
            affected_users TEXT,
            affected_devices TEXT,
            affected_ips TEXT,
            threat_categories TEXT,
            mitre_techniques TEXT,
            ioc_count INTEGER DEFAULT 0,
            investigation_priority TEXT DEFAULT 'LOW',
            recommendation TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))


    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS cluster_risk_assessments (
            cluster_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            risk_score DOUBLE PRECISION DEFAULT 0,
            severity TEXT DEFAULT 'LOW',
            confidence DOUBLE PRECISION DEFAULT 0,
            risk_components TEXT,
            reason_codes TEXT,
            recommendation TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))


    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS attack_campaigns (
            campaign_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            cluster_id TEXT UNIQUE,
            name TEXT,
            status TEXT DEFAULT 'ACTIVE',
            risk_score DOUBLE PRECISION DEFAULT 0,
            confidence DOUBLE PRECISION DEFAULT 0,
            severity TEXT DEFAULT 'LOW',
            primary_category TEXT,
            first_seen TEXT,
            last_seen TEXT,
            event_count INTEGER DEFAULT 0,
            affected_users TEXT,
            affected_devices TEXT,
            affected_ips TEXT,
            mitre_techniques TEXT,
            threat_dna TEXT,
            investigation_priority TEXT DEFAULT 'LOW',
            recommendation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))


    cur.execute(db_sql("""
        CREATE TABLE IF NOT EXISTS attack_campaign_edges (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            relationship TEXT NOT NULL,
            weight DOUBLE PRECISION DEFAULT 1,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(campaign_id, source_id, target_id, relationship)
        )
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_campaign_tenant
        ON attack_campaigns(tenant_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_campaign_cluster
        ON attack_campaigns(cluster_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_campaign_edges_campaign
        ON attack_campaign_edges(campaign_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_cluster_intel_tenant
        ON cluster_intelligence(tenant_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_event_corr_source
        ON event_correlations(source_event_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_event_corr_related
        ON event_correlations(related_event_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_event_corr_tenant
        ON event_correlations(tenant_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_cluster_tenant
        ON correlation_clusters(tenant_id)
    """))

    cur.execute(db_sql("""
        CREATE INDEX IF NOT EXISTS idx_cluster_members_event
        ON correlation_cluster_members(event_id)
    """))

    conn.commit()
    conn.close()


def _event_is_correlatable(event):
    try:
        score = float(event.get("risk_score") or 0)
    except Exception:
        score = 0

    category = normalize(event.get("threat_category"))

    return score >= 50 or category not in {"", "safe"}


def _score_pair(current, other):
    reasons = []
    score = 0.0

    if normalize(current.get("tenant_id")) != normalize(other.get("tenant_id")):
        return 0.0, []

    if normalize(current.get("user")) and (
        normalize(current.get("user")) == normalize(other.get("user"))
    ):
        score += 0.35
        reasons.append("same_user")

    current_host = normalize(
        current.get("hostname") or current.get("device")
    )
    other_host = normalize(
        other.get("hostname") or other.get("device")
    )

    if current_host and current_host == other_host:
        score += 0.30
        reasons.append("same_device")

    if normalize(current.get("ip")) and (
        normalize(current.get("ip")) == normalize(other.get("ip"))
    ):
        score += 0.30
        reasons.append("same_ip")

    for field, reason, weight in (
        ("domain", "same_domain", 0.25),
        ("url", "same_url", 0.25),
        ("ioc", "same_ioc", 0.25),
        ("campaign_id", "same_campaign", 0.35),
    ):
        a = normalize(current.get(field))
        b = normalize(other.get(field))

        if a and b and a == b:
            score += weight
            reasons.append(reason)

    current_category = normalize(
        current.get("threat_category")
    )
    other_category = normalize(
        other.get("threat_category")
    )

    if current_category and current_category == other_category:
        score += 0.10
        reasons.append("same_threat_category")

    current_ts = parse_timestamp(current.get("timestamp"))
    other_ts = parse_timestamp(other.get("timestamp"))

    if current_ts and other_ts:
        minutes = abs(
            (current_ts - other_ts).total_seconds()
        ) / 60.0

        if minutes > CORRELATION_WINDOW_MINUTES:
            return 0.0, []

        score += max(
            0.0,
            0.10 * (
                1 - minutes / CORRELATION_WINDOW_MINUTES
            )
        )

    return min(score, 1.0), reasons


def _build_cluster(event, related):
    event_ids = [event.get("event_id")]

    for item in related:
        if item.get("event_id"):
            event_ids.append(item["event_id"])

    cluster_id = cluster_id_for(event_ids)

    all_events = [event]

    conn = get_conn()
    cur = conn.cursor()

    for item in related:
        cur.execute(
            db_sql("""
                SELECT *
                FROM security_events
                WHERE event_id = ?
                LIMIT 1
            """),
            (item["event_id"],)
        )

        row = cur.fetchone()

        if row:
            all_events.append(dict(row))

    timestamps = []

    for item in all_events:
        ts = parse_timestamp(item.get("timestamp"))

        if ts:
            timestamps.append(ts)

    first_seen = min(timestamps).isoformat() if timestamps else None
    last_seen = max(timestamps).isoformat() if timestamps else None

    categories = [
        item.get("threat_category")
        for item in all_events
        if normalize(item.get("threat_category"))
    ]

    users = [
        item.get("user")
        for item in all_events
        if normalize(item.get("user"))
    ]

    devices = [
        item.get("hostname") or item.get("device")
        for item in all_events
        if normalize(item.get("hostname") or item.get("device"))
    ]

    ips = [
        item.get("ip")
        for item in all_events
        if normalize(item.get("ip"))
    ]

    primary_category = (
        max(
            set(categories),
            key=categories.count
        )
        if categories
        else "Unknown"
    )

    primary_user = users[0] if users else None
    primary_device = devices[0] if devices else None
    primary_ip = ips[0] if ips else None

    scores = [
        float(item.get("correlation_score") or 1)
        for item in related
    ]

    confidence = (
        sum(scores) / len(scores)
        if scores
        else 1.0
    )

    cur.execute(
        db_sql("""
            INSERT INTO correlation_clusters (
                cluster_id,
                tenant_id,
                confidence,
                primary_category,
                primary_user,
                primary_device,
                primary_ip,
                event_count,
                first_seen,
                last_seen,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cluster_id)
            DO UPDATE SET
                confidence = EXCLUDED.confidence,
                primary_category = EXCLUDED.primary_category,
                primary_user = EXCLUDED.primary_user,
                primary_device = EXCLUDED.primary_device,
                primary_ip = EXCLUDED.primary_ip,
                event_count = EXCLUDED.event_count,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                status = EXCLUDED.status,
                updated_at = CURRENT_TIMESTAMP
        """),
        (
            cluster_id,
            event.get("tenant_id") or "demo",
            confidence,
            primary_category,
            primary_user,
            primary_device,
            primary_ip,
            len(all_events),
            first_seen,
            last_seen,
            "ACTIVE",
        )
    )

    cur.execute(
        db_sql("""
            INSERT INTO correlation_cluster_members (
                cluster_id,
                event_id,
                correlation_score,
                reasons
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT (cluster_id, event_id)
            DO UPDATE SET
                correlation_score = EXCLUDED.correlation_score,
                reasons = EXCLUDED.reasons
        """),
        (
            cluster_id,
            event.get("event_id"),
            1.0,
            json.dumps(["primary_event"]),
        )
    )

    for item in related:
        cur.execute(
            db_sql("""
                INSERT INTO correlation_cluster_members (
                    cluster_id,
                    event_id,
                    correlation_score,
                    reasons
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT (cluster_id, event_id)
                DO UPDATE SET
                    correlation_score = EXCLUDED.correlation_score,
                    reasons = EXCLUDED.reasons
            """),
            (
                cluster_id,
                item["event_id"],
                item["correlation_score"],
                json.dumps(item["reasons"]),
            )
        )

    conn.commit()
    conn.close()

    return {
        "cluster_id": cluster_id,
        "confidence": round(confidence, 3),
        "event_count": len(all_events),
        "primary_category": primary_category,
        "primary_user": primary_user,
        "primary_device": primary_device,
        "primary_ip": primary_ip,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "status": "ACTIVE",
    }


def assess_cluster_risk(
    cluster_id,
    max_risk,
    confidence,
    event_count,
    velocity,
    users,
    devices,
    ips,
    ioc_count,
    events,
):
    components = {}
    reasons = []

    # Core risk contribution.
    risk_component = min(60.0, max_risk * 0.60)
    components["base_risk"] = round(risk_component, 2)

    if max_risk >= 80:
        reasons.append("high_risk_event_ge_80")
    elif max_risk >= 70:
        reasons.append("elevated_risk_event_ge_70")
    elif max_risk >= 50:
        reasons.append("suspicious_risk_event_ge_50")

    # Rapid activity.
    velocity_component = min(15.0, velocity * 5.0)
    components["velocity"] = round(velocity_component, 2)

    if velocity >= 1.0:
        reasons.append("rapid_event_velocity")

    # Multiple correlated events.
    if event_count >= 5:
        components["event_volume"] = 15.0
        reasons.append("high_event_volume")
    elif event_count >= 3:
        components["event_volume"] = 8.0
        reasons.append("repeated_correlated_activity")
    else:
        components["event_volume"] = 0.0

    # Active incident evidence.
    has_incident = any(
        str(e.get("event_type", "")).lower() == "incident_event"
        for e in events
    )

    if has_incident:
        components["active_incident"] = 20.0
        reasons.append("active_incident_present")
    else:
        components["active_incident"] = 0.0

    # Multiple identities/assets increase blast radius.
    entity_component = 0.0

    if len(users) > 1:
        entity_component += 5.0
        reasons.append("multiple_users_affected")

    if len(devices) > 1:
        entity_component += 5.0
        reasons.append("multiple_devices_affected")

    if len(ips) > 1:
        entity_component += 5.0
        reasons.append("multiple_ips_affected")

    components["entity_spread"] = entity_component

    # IOC density.
    if ioc_count >= 5:
        components["ioc_density"] = 10.0
        reasons.append("high_ioc_density")
    elif ioc_count >= 2:
        components["ioc_density"] = 5.0
        reasons.append("multiple_iocs")
    else:
        components["ioc_density"] = 0.0

    # Confidence contributes modestly rather than dominating.
    confidence_component = min(5.0, confidence * 0.05)
    components["confidence"] = round(confidence_component, 2)

    if confidence >= 90:
        reasons.append("high_correlation_confidence")

    score = min(
        100.0,
        sum(components.values())
    )

    # Explicit, explainable severity thresholds.
    if score >= 70:
        severity = "CRITICAL"
        priority = "IMMEDIATE"
        recommendation = (
            "Immediate investigation. Review the complete cluster, "
            "affected identities, devices, network indicators, "
            "MITRE techniques, and any active incident."
        )
    elif score >= 50:
        severity = "HIGH"
        priority = "HIGH"
        recommendation = (
            "Investigate the cluster promptly and validate the "
            "relationship between its correlated events."
        )
    elif score >= 30:
        severity = "MEDIUM"
        priority = "MEDIUM"
        recommendation = (
            "Monitor the cluster and investigate if related activity "
            "continues or expands."
        )
    else:
        severity = "LOW"
        priority = "LOW"
        recommendation = (
            "Continue monitoring. No immediate escalation is required."
        )

    return {
        "cluster_id": cluster_id,
        "risk_score": round(score, 2),
        "severity": severity,
        "priority": priority,
        "confidence": round(confidence, 2),
        "components": components,
        "reason_codes": reasons,
        "recommendation": recommendation,
    }


def build_cluster_intelligence(cluster_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM correlation_clusters
            WHERE cluster_id = ?
            LIMIT 1
        """),
        (cluster_id,)
    )

    cluster = cur.fetchone()

    if not cluster:
        conn.close()
        return None

    cluster = dict(cluster)

    cur.execute(
        db_sql("""
            SELECT e.*
            FROM correlation_cluster_members m
            JOIN security_events e
              ON e.event_id = m.event_id
            WHERE m.cluster_id = ?
            ORDER BY e.timestamp ASC
        """),
        (cluster_id,)
    )

    events = [dict(row) for row in cur.fetchall()]
    conn.close()

    if not events:
        return None

    users = sorted({
        str(e.get("user"))
        for e in events
        if e.get("user")
    })

    devices = sorted({
        str(e.get("hostname") or e.get("device"))
        for e in events
        if e.get("hostname") or e.get("device")
    })

    ips = set()

    for e in events:
        ip_value = e.get("ip")

        if ip_value:
            ips.add(str(ip_value))

        # Recover IP from raw_event when necessary.
        if not ip_value:
            raw = e.get("raw_event")

            if isinstance(raw, str):
                try:
                    import json as _json
                    raw = _json.loads(raw)
                except Exception:
                    raw = {}

            if isinstance(raw, dict) and raw.get("ip"):
                ips.add(str(raw["ip"]))

    ips = sorted(ips)

    categories = sorted({
        str(e.get("threat_category"))
        for e in events
        if e.get("threat_category")
        and str(e.get("threat_category")).lower() != "safe"
    })

    mitre = set()
    ioc_values = set()
    timestamps = []

    for event in events:
        ts = parse_timestamp(event.get("timestamp"))

        if ts:
            timestamps.append(ts)

        mitre_value = event.get("mitre_technique")

        if mitre_value:
            try:
                decoded = json.loads(
                    mitre_value
                ) if isinstance(
                    mitre_value, str
                ) else mitre_value

                if isinstance(decoded, dict):
                    technique_id = decoded.get("id")
                    technique_name = (
                        decoded.get("technique")
                        or decoded.get("name")
                    )

                    if technique_id and technique_id not in {
                        "-", "TA0000"
                    }:
                        mitre.add(
                            f"{technique_id} - "
                            f"{technique_name or 'Unknown'}"
                        )
                elif decoded:
                    mitre.add(str(decoded))

            except Exception:
                text = str(mitre_value)

                if text and "No Mapping" not in text:
                    mitre.add(text)

        for field in ("ioc", "ip", "domain", "url"):
            value = event.get(field)

            if value:
                ioc_values.add(str(value))

    scores = []

    for event in events:
        try:
            scores.append(
                float(event.get("risk_score") or 0)
            )
        except Exception:
            pass

    max_risk = max(scores) if scores else 0
    average_risk = (
        sum(scores) / len(scores)
        if scores
        else 0
    )

    event_count = len(events)

    if len(timestamps) >= 2:
        first_seen_dt = min(timestamps)
        last_seen_dt = max(timestamps)

        minutes = max(
            (
                last_seen_dt - first_seen_dt
            ).total_seconds() / 60.0,
            0.1
        )

        velocity = event_count / minutes

    else:
        velocity = float(event_count)

    confidence = float(
        cluster.get("confidence") or 0
    ) * 100.0

    risk = assess_cluster_risk(
        cluster_id=cluster_id,
        max_risk=max_risk,
        confidence=confidence,
        event_count=event_count,
        velocity=velocity,
        users=users,
        devices=devices,
        ips=ips,
        ioc_count=len(ioc_values),
        events=events,
    )

    first_seen = (
        min(timestamps).isoformat()
        if timestamps
        else None
    )

    last_seen = (
        max(timestamps).isoformat()
        if timestamps
        else None
    )

    intelligence = {
        "cluster_id": cluster_id,
        "tenant_id": cluster.get("tenant_id") or "demo",
        "risk_score": risk["risk_score"],
        "average_risk": round(average_risk, 2),
        "confidence": risk["confidence"],
        "severity": risk["severity"],
        "event_count": event_count,
        "event_velocity": round(velocity, 4),
        "affected_users": users,
        "affected_devices": devices,
        "affected_ips": ips,
        "threat_categories": categories,
        "mitre_techniques": sorted(mitre),
        "ioc_count": len(ioc_values),
        "investigation_priority": risk["priority"],
        "recommendation": risk["recommendation"],
        "risk_components": risk["components"],
        "reason_codes": risk["reason_codes"],
        "first_seen": first_seen,
        "last_seen": last_seen,
    }

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            INSERT INTO cluster_intelligence (
                cluster_id,
                tenant_id,
                risk_score,
                confidence,
                severity,
                event_velocity,
                affected_users,
                affected_devices,
                affected_ips,
                threat_categories,
                mitre_techniques,
                ioc_count,
                investigation_priority,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cluster_id)
            DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                confidence = EXCLUDED.confidence,
                severity = EXCLUDED.severity,
                event_velocity = EXCLUDED.event_velocity,
                affected_users = EXCLUDED.affected_users,
                affected_devices = EXCLUDED.affected_devices,
                affected_ips = EXCLUDED.affected_ips,
                threat_categories = EXCLUDED.threat_categories,
                mitre_techniques = EXCLUDED.mitre_techniques,
                ioc_count = EXCLUDED.ioc_count,
                investigation_priority = EXCLUDED.investigation_priority,
                recommendation = EXCLUDED.recommendation,
                updated_at = CURRENT_TIMESTAMP
        """),
        (
            intelligence["cluster_id"],
            intelligence["tenant_id"],
            intelligence["risk_score"],
            intelligence["confidence"],
            intelligence["severity"],
            intelligence["event_velocity"],
            json.dumps(
                intelligence["affected_users"]
            ),
            json.dumps(
                intelligence["affected_devices"]
            ),
            json.dumps(
                intelligence["affected_ips"]
            ),
            json.dumps(
                intelligence["threat_categories"]
            ),
            json.dumps(
                intelligence["mitre_techniques"]
            ),
            intelligence["ioc_count"],
            intelligence["investigation_priority"],
            intelligence["recommendation"],
        )
    )

    cur.execute(
        db_sql("""
            INSERT INTO cluster_risk_assessments (
                cluster_id,
                tenant_id,
                risk_score,
                severity,
                confidence,
                risk_components,
                reason_codes,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cluster_id)
            DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                severity = EXCLUDED.severity,
                confidence = EXCLUDED.confidence,
                risk_components = EXCLUDED.risk_components,
                reason_codes = EXCLUDED.reason_codes,
                recommendation = EXCLUDED.recommendation,
                updated_at = CURRENT_TIMESTAMP
        """),
        (
            cluster_id,
            intelligence["tenant_id"],
            risk["risk_score"],
            risk["severity"],
            risk["confidence"],
            json.dumps(risk["components"]),
            json.dumps(risk["reason_codes"]),
            risk["recommendation"],
        )
    )

    conn.commit()
    conn.close()

    return intelligence


def get_cluster_risk_assessment(cluster_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM cluster_risk_assessments
            WHERE cluster_id = ?
            LIMIT 1
        """),
        (cluster_id,)
    )

    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    result = dict(row)

    for field in (
        "risk_components",
        "reason_codes",
    ):
        value = result.get(field)

        if isinstance(value, str):
            try:
                result[field] = json.loads(value)
            except Exception:
                result[field] = {}

    return result



def build_attack_campaign(cluster_id):
    cluster = get_correlation_cluster(cluster_id)

    if not cluster:
        return None

    intelligence = cluster.get("intelligence") or {}
    risk = cluster.get("risk_assessment") or {}

    campaign_id = f"CAMP-{cluster_id.replace('CLUSTER-', '')}"

    category = (
        intelligence.get("threat_categories", ["Unknown"])[0]
        if intelligence.get("threat_categories")
        else "Unknown"
    )

    name = f"{category} Campaign"

    campaign = {
        "campaign_id": campaign_id,
        "tenant_id": cluster.get("tenant_id") or "demo",
        "cluster_id": cluster_id,
        "name": name,
        "status": cluster.get("status", "ACTIVE"),
        "risk_score": float(
            risk.get("risk_score")
            or intelligence.get("risk_score")
            or 0
        ),
        "confidence": float(
            risk.get("confidence")
            or intelligence.get("confidence")
            or 0
        ),
        "severity": (
            risk.get("severity")
            or intelligence.get("severity")
            or "LOW"
        ),
        "primary_category": category,
        "first_seen": cluster.get("first_seen"),
        "last_seen": cluster.get("last_seen"),
        "event_count": int(
            cluster.get("event_count") or 0
        ),
        "affected_users": (
            intelligence.get("affected_users") or []
        ),
        "affected_devices": (
            intelligence.get("affected_devices") or []
        ),
        "affected_ips": (
            intelligence.get("affected_ips") or []
        ),
        "mitre_techniques": (
            intelligence.get("mitre_techniques") or []
        ),
        "investigation_priority": (
            intelligence.get("investigation_priority")
            or "LOW"
        ),
        "recommendation": (
            intelligence.get("recommendation")
            or "Continue monitoring."
        ),
    }

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            INSERT INTO attack_campaigns (
                campaign_id,
                tenant_id,
                cluster_id,
                name,
                status,
                risk_score,
                confidence,
                severity,
                primary_category,
                first_seen,
                last_seen,
                event_count,
                affected_users,
                affected_devices,
                affected_ips,
                mitre_techniques,
                threat_dna,
                investigation_priority,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (campaign_id)
            DO UPDATE SET
                name = EXCLUDED.name,
                status = EXCLUDED.status,
                risk_score = EXCLUDED.risk_score,
                confidence = EXCLUDED.confidence,
                severity = EXCLUDED.severity,
                primary_category = EXCLUDED.primary_category,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                event_count = EXCLUDED.event_count,
                affected_users = EXCLUDED.affected_users,
                affected_devices = EXCLUDED.affected_devices,
                affected_ips = EXCLUDED.affected_ips,
                mitre_techniques = EXCLUDED.mitre_techniques,
                investigation_priority = EXCLUDED.investigation_priority,
                recommendation = EXCLUDED.recommendation,
                updated_at = CURRENT_TIMESTAMP
        """),
        (
            campaign["campaign_id"],
            campaign["tenant_id"],
            campaign["cluster_id"],
            campaign["name"],
            campaign["status"],
            campaign["risk_score"],
            campaign["confidence"],
            campaign["severity"],
            campaign["primary_category"],
            campaign["first_seen"],
            campaign["last_seen"],
            campaign["event_count"],
            json.dumps(campaign["affected_users"]),
            json.dumps(campaign["affected_devices"]),
            json.dumps(campaign["affected_ips"]),
            json.dumps(campaign["mitre_techniques"]),
            json.dumps(campaign.get("threat_dna")) if campaign.get("threat_dna") is not None else None,
            campaign["investigation_priority"],
            campaign["recommendation"],
        )
    )

    # Cluster ? event graph
    members = cluster.get("members") or []

    for member in members:
        event_id = member.get("event_id")

        if not event_id:
            continue

        edge_id = (
            f"{campaign_id}:"
            f"{campaign_id}:"
            f"{event_id}"
        )

        cur.execute(
            db_sql("""
                INSERT INTO attack_campaign_edges (
                    id,
                    campaign_id,
                    source_id,
                    target_id,
                    relationship,
                    weight,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    campaign_id,
                    source_id,
                    target_id,
                    relationship
                )
                DO UPDATE SET
                    weight = EXCLUDED.weight,
                    metadata = EXCLUDED.metadata
            """),
            (
                edge_id,
                campaign_id,
                campaign_id,
                event_id,
                "CONTAINS_EVENT",
                float(
                    member.get("correlation_score") or 1
                ),
                json.dumps({
                    "event_type": member.get("event_type"),
                    "threat_category": member.get(
                        "threat_category"
                    ),
                }),
            )
        )

    # Campaign ? MITRE graph
    for technique in campaign["mitre_techniques"]:
        technique_id = (
            f"{campaign_id}:MITRE:"
            f"{technique}"
        )

        cur.execute(
            db_sql("""
                INSERT INTO attack_campaign_edges (
                    id,
                    campaign_id,
                    source_id,
                    target_id,
                    relationship,
                    weight,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    campaign_id,
                    source_id,
                    target_id,
                    relationship
                )
                DO UPDATE SET
                    weight = EXCLUDED.weight
            """),
            (
                technique_id,
                campaign_id,
                campaign_id,
                technique,
                "USES_MITRE_TECHNIQUE",
                1.0,
                "{}",
            )
        )

    # Campaign ? affected entities
    for user in campaign["affected_users"]:
        edge_id = f"{campaign_id}:USER:{user}"

        cur.execute(
            db_sql("""
                INSERT INTO attack_campaign_edges (
                    id,
                    campaign_id,
                    source_id,
                    target_id,
                    relationship,
                    weight,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    campaign_id,
                    source_id,
                    target_id,
                    relationship
                )
                DO UPDATE SET
                    weight = EXCLUDED.weight
            """),
            (
                edge_id,
                campaign_id,
                campaign_id,
                f"user:{user}",
                "AFFECTS_USER",
                1.0,
                "{}",
            )
        )

    for device in campaign["affected_devices"]:
        edge_id = f"{campaign_id}:DEVICE:{device}"

        cur.execute(
            db_sql("""
                INSERT INTO attack_campaign_edges (
                    id,
                    campaign_id,
                    source_id,
                    target_id,
                    relationship,
                    weight,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    campaign_id,
                    source_id,
                    target_id,
                    relationship
                )
                DO UPDATE SET
                    weight = EXCLUDED.weight
            """),
            (
                edge_id,
                campaign_id,
                campaign_id,
                f"device:{device}",
                "AFFECTS_DEVICE",
                1.0,
                "{}",
            )
        )

    for ip in campaign["affected_ips"]:
        edge_id = f"{campaign_id}:IP:{ip}"

        cur.execute(
            db_sql("""
                INSERT INTO attack_campaign_edges (
                    id,
                    campaign_id,
                    source_id,
                    target_id,
                    relationship,
                    weight,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    campaign_id,
                    source_id,
                    target_id,
                    relationship
                )
                DO UPDATE SET
                    weight = EXCLUDED.weight
            """),
            (
                edge_id,
                campaign_id,
                campaign_id,
                f"ip:{ip}",
                "USES_IP",
                1.0,
                "{}",
            )
        )

    conn.commit()
    conn.close()

    return campaign



def build_campaign_timeline(campaign_id):
    campaign = get_attack_campaign(campaign_id)

    if not campaign:
        return None

    cluster_id = campaign.get("cluster_id")

    if not cluster_id:
        return {
            "campaign_id": campaign_id,
            "events": [],
            "event_count": 0,
        }

    cluster = get_correlation_cluster(cluster_id)

    if not cluster:
        return {
            "campaign_id": campaign_id,
            "events": [],
            "event_count": 0,
        }

    members = cluster.get("members") or []

    timeline = []

    for member in members:
        event_id = member.get("event_id")

        if not event_id:
            continue

        event_type = member.get(
            "event_type",
            "security_event"
        )

        category = member.get(
            "threat_category",
            "Unknown"
        )

        risk_score = float(
            member.get("risk_score") or 0
        )

        timestamp = member.get("timestamp")

        if event_type == "scan_event":
            phase = "DETECTION"
        elif event_type == "alert_event":
            phase = "ALERT"
        elif event_type == "incident_event":
            phase = "INCIDENT"
        elif event_type == "auto_response_event":
            phase = "RESPONSE"
        else:
            phase = "SECURITY EVENT"

        timeline.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "phase": phase,
            "event_type": event_type,
            "category": category,
            "risk_score": risk_score,
            "user": member.get("user"),
            "device": (
                member.get("hostname")
                or member.get("device")
            ),
            "ip": member.get("ip"),
            "correlation_score": float(
                member.get("correlation_score") or 0
            ),
        })

    timeline.sort(
        key=lambda item: (
            item.get("timestamp") or ""
        )
    )

    # Add campaign-level opening/closing context.
    campaign_start = campaign.get("first_seen")
    campaign_end = campaign.get("last_seen")

    return {
        "campaign_id": campaign_id,
        "cluster_id": cluster_id,
        "first_seen": campaign_start,
        "last_seen": campaign_end,
        "event_count": len(timeline),
        "events": timeline,
    }



def build_threat_dna(campaign_id):
    """Build a behavioral Threat DNA profile for an attack campaign."""

    campaign = get_attack_campaign(campaign_id)

    if not campaign:
        return {
            "campaign_id": campaign_id,
            "behavioral_signature": [],
            "ioc_profile": {},
            "mitre_techniques": [],
            "attack_stages": [],
            "categories": [],
            "recurrence": 0,
            "frequency": 0,
            "status": "not_found"
        }

    timeline_data = get_campaign_timeline(campaign_id) or []

    if isinstance(timeline_data, dict):
        timeline = (
            timeline_data.get("events")
            or timeline_data.get("timeline")
            or []
        )
    else:
        timeline = timeline_data

    if isinstance(timeline, dict):
        timeline = [timeline]

    categories = []
    stages = []
    event_types = []
    mitre = list(campaign.get("mitre_techniques") or [])

    ioc_profile = {
        "ips": [],
        "users": [],
        "devices": [],
        "event_ids": []
    }

    for event in timeline:
        if not isinstance(event, dict):
            continue

        category = event.get("category")
        phase = event.get("phase")
        event_type = event.get("event_type")

        if category and category not in categories:
            categories.append(category)

        if phase and phase not in stages:
            stages.append(phase)

        if event_type and event_type not in event_types:
            event_types.append(event_type)

        if event.get("ip") and event["ip"] not in ioc_profile["ips"]:
            ioc_profile["ips"].append(event["ip"])

        if event.get("user") and event["user"] not in ioc_profile["users"]:
            ioc_profile["users"].append(event["user"])

        if event.get("device") and event["device"] not in ioc_profile["devices"]:
            ioc_profile["devices"].append(event["device"])

        if event.get("event_id"):
            ioc_profile["event_ids"].append(event["event_id"])

    behavioral_signature = []

    behavioral_signature.extend(
        f"Category:{category}"
        for category in categories
    )

    behavioral_signature.extend(
        f"Phase:{phase}"
        for phase in stages
    )

    behavioral_signature.extend(
        f"EventType:{event_type}"
        for event_type in event_types
    )

    behavioral_signature.extend(
        f"MITRE:{technique}"
        for technique in mitre
        if technique
    )

    ioc_profile = {
        key: values
        for key, values in ioc_profile.items()
        if values
    }

    frequency = len(timeline)

    return {
        "campaign_id": campaign_id,
        "behavioral_signature": behavioral_signature,
        "ioc_profile": ioc_profile,
        "mitre_techniques": mitre,
        "attack_stages": stages,
        "categories": categories,
        "recurrence": max(frequency - 1, 0),
        "frequency": frequency,
        "status": "ready"
    }



def get_campaign_timeline(campaign_id):
    return build_campaign_timeline(campaign_id)



def get_attack_campaign(campaign_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM attack_campaigns
            WHERE campaign_id = ?
            LIMIT 1
        """),
        (campaign_id,)
    )

    row = cur.fetchone()

    if not row:
        conn.close()
        return None

    campaign = dict(row)

    for field in (
        "affected_users",
        "affected_devices",
        "affected_ips",
        "mitre_techniques",
        "threat_dna",
    ):
        value = campaign.get(field)

        if isinstance(value, str):
            try:
                campaign[field] = json.loads(value)
            except Exception:
                campaign[field] = []

    cur.execute(
        db_sql("""
            SELECT *
            FROM attack_campaign_edges
            WHERE campaign_id = ?
            ORDER BY created_at ASC
        """),
        (campaign_id,)
    )

    campaign["edges"] = [
        dict(edge)
        for edge in cur.fetchall()
    ]

    conn.close()

    return campaign


def get_attack_campaigns(
    tenant_id=None,
    limit=50
):
    conn = get_conn()
    cur = conn.cursor()

    if tenant_id:
        cur.execute(
            db_sql("""
                SELECT *
                FROM attack_campaigns
                WHERE tenant_id = ?
                ORDER BY risk_score DESC, updated_at DESC
                LIMIT ?
            """),
            (tenant_id, limit)
        )
    else:
        cur.execute(
            db_sql("""
                SELECT *
                FROM attack_campaigns
                ORDER BY risk_score DESC, updated_at DESC
                LIMIT ?
            """),
            (limit,)
        )

    rows = cur.fetchall()
    conn.close()

    results = []

    for row in rows:
        item = dict(row)

        for field in (
            "affected_users",
            "affected_devices",
            "affected_ips",
            "mitre_techniques",
            "threat_dna",
        ):
            value = item.get(field)

            if isinstance(value, str):
                try:
                    item[field] = json.loads(value)
                except Exception:
                    item[field] = []

        results.append(item)

    return results



def get_cluster_intelligence(cluster_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM cluster_intelligence
            WHERE cluster_id = ?
            LIMIT 1
        """),
        (cluster_id,)
    )

    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    result = dict(row)

    for field in (
        "affected_users",
        "affected_devices",
        "affected_ips",
        "threat_categories",
        "mitre_techniques",
    ):
        value = result.get(field)

        if isinstance(value, str):
            try:
                result[field] = json.loads(value)
            except Exception:
                result[field] = []

    return result


def get_cluster_intelligence_list(
    tenant_id=None,
    limit=50
):
    conn = get_conn()
    cur = conn.cursor()

    if tenant_id:
        cur.execute(
            db_sql("""
                SELECT *
                FROM cluster_intelligence
                WHERE tenant_id = ?
                ORDER BY risk_score DESC, updated_at DESC
                LIMIT ?
            """),
            (tenant_id, limit)
        )
    else:
        cur.execute(
            db_sql("""
                SELECT *
                FROM cluster_intelligence
                ORDER BY risk_score DESC, updated_at DESC
                LIMIT ?
            """),
            (limit,)
        )

    rows = cur.fetchall()
    conn.close()

    results = []

    for row in rows:
        item = dict(row)

        for field in (
            "affected_users",
            "affected_devices",
            "affected_ips",
            "threat_categories",
            "mitre_techniques",
        ):
            value = item.get(field)

            if isinstance(value, str):
                try:
                    item[field] = json.loads(value)
                except Exception:
                    item[field] = []

        results.append(item)

    return results


def correlate_event(
    event: dict,
    window_minutes=CORRELATION_WINDOW_MINUTES
):
    if not event:
        return {
            "correlation_id": None,
            "cluster": None,
            "related_events": [],
            "count": 0,
        }

    if not _event_is_correlatable(event):
        return {
            "correlation_id": event.get("correlation_id"),
            "cluster": None,
            "related_events": [],
            "count": 0,
        }

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM security_events
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT 200
        """),
        (event.get("tenant_id") or "demo",)
    )

    rows = cur.fetchall()
    conn.close()

    related = []

    current_time = (
        parse_timestamp(event.get("timestamp"))
        or utc_now()
    )

    for row in rows:
        other = dict(row)

        if other.get("event_id") == event.get("event_id"):
            continue

        other_time = parse_timestamp(
            other.get("timestamp")
        )

        if not other_time:
            continue

        age_minutes = abs(
            (current_time - other_time).total_seconds()
        ) / 60.0

        if age_minutes > window_minutes:
            continue

        if not _event_is_correlatable(other):
            continue

        score, reasons = _score_pair(
            event,
            other
        )

        if score < MIN_CORRELATION_SCORE:
            continue

        related.append({
            "event_id": other.get("event_id"),
            "event_type": other.get("event_type"),
            "threat_category": other.get(
                "threat_category"
            ),
            "risk_score": other.get("risk_score"),
            "correlation_score": round(score, 3),
            "reasons": reasons,
        })

    related.sort(
        key=lambda x: x["correlation_score"],
        reverse=True
    )

    related = related[:25]

    correlation_id = (
        event.get("correlation_id")
        or f"CORR-{uuid.uuid4().hex[:12]}"
    )

    conn = get_conn()
    cur = conn.cursor()

    for item in related:
        pair_id = (
            f"{event['event_id']}:{item['event_id']}"
        )

        cur.execute(
            db_sql("""
                INSERT INTO event_correlations (
                    id,
                    tenant_id,
                    source_event_id,
                    related_event_id,
                    correlation_score,
                    reasons
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (source_event_id, related_event_id)
                DO UPDATE SET
                    correlation_score = EXCLUDED.correlation_score,
                    reasons = EXCLUDED.reasons
            """),
            (
                pair_id,
                event.get("tenant_id") or "demo",
                event.get("event_id"),
                item["event_id"],
                item["correlation_score"],
                json.dumps(item["reasons"]),
            )
        )

    conn.commit()
    conn.close()

    cluster = None

    if related:
        cluster = _build_cluster(
            event,
            related
        )

        if cluster:
            cluster_intelligence = build_cluster_intelligence(
                cluster["cluster_id"]
            )

            if cluster_intelligence:
                cluster["intelligence"] = cluster_intelligence

            try:
                campaign = build_attack_campaign(
                    cluster["cluster_id"]
                )

                if campaign:
                    cluster["campaign"] = campaign

            except Exception as campaign_error:
                print(
                    "[CAMPAIGN] build failed:",
                    campaign_error
                )

    return {
        "correlation_id": correlation_id,
        "cluster": cluster,
        "related_events": related,
        "count": len(related),
    }


def get_event_correlations(event_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM event_correlations
            WHERE source_event_id = ?
               OR related_event_id = ?
            ORDER BY correlation_score DESC
        """),
        (event_id, event_id)
    )

    rows = cur.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_correlation_cluster(cluster_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        db_sql("""
            SELECT *
            FROM correlation_clusters
            WHERE cluster_id = ?
            LIMIT 1
        """),
        (cluster_id,)
    )

    cluster = cur.fetchone()

    if not cluster:
        conn.close()
        return None

    cur.execute(
        db_sql("""
            SELECT
                m.event_id,
                m.correlation_score,
                m.reasons,
                e.event_type,
                e.threat_category,
                e.risk_score,
                e.user,
                e.hostname,
                e.ip,
                e.timestamp
            FROM correlation_cluster_members m
            JOIN security_events e
              ON e.event_id = m.event_id
            WHERE m.cluster_id = ?
            ORDER BY e.timestamp ASC
        """),
        (cluster_id,)
    )

    members = cur.fetchall()
    conn.close()

    result = dict(cluster)
    result["members"] = [dict(row) for row in members]
    result["intelligence"] = get_cluster_intelligence(cluster_id)
    result["risk_assessment"] = get_cluster_risk_assessment(cluster_id)

    return result


def get_correlation_clusters(
    tenant_id=None,
    limit=50
):
    conn = get_conn()
    cur = conn.cursor()

    if tenant_id:
        cur.execute(
            db_sql("""
                SELECT *
                FROM correlation_clusters
                WHERE tenant_id = ?
                ORDER BY updated_at DESC
                LIMIT ?
            """),
            (tenant_id, limit)
        )
    else:
        cur.execute(
            db_sql("""
                SELECT *
                FROM correlation_clusters
                ORDER BY updated_at DESC
                LIMIT ?
            """),
            (limit,)
        )

    rows = cur.fetchall()
    conn.close()

    return [dict(row) for row in rows]


