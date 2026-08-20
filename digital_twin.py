import sqlite3
from datetime import datetime

from attack_graph import get_conn


# ============================================================
# DIGITAL TWIN — ASSET TYPES
# ============================================================

ASSET_TYPES = {
    "USER",
    "DEVICE",
    "SERVER",
    "APPLICATION",
    "NETWORK",
    "SECURITY_CONTROL",
    "VULNERABILITY",
    "THREAT",
    "INCIDENT",
}


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_digital_twin_db():
    conn = get_conn()
    cursor = conn.cursor()

    # --------------------------------------------------------
    # DIGITAL TWIN ASSETS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS digital_twin_assets (
            id TEXT PRIMARY KEY,

            tenant_id TEXT,

            asset_type TEXT NOT NULL,

            name TEXT NOT NULL,

            description TEXT,

            status TEXT DEFAULT 'active',

            criticality REAL DEFAULT 0,

            exposure REAL DEFAULT 0,

            risk_score REAL DEFAULT 0,

            owner TEXT,

            location TEXT,

            os TEXT,

            ip_address TEXT,

            hostname TEXT,

            first_seen TIMESTAMP,

            last_seen TIMESTAMP,

            metadata TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # DIGITAL TWIN RELATIONSHIPS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS digital_twin_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            tenant_id TEXT,

            source_id TEXT NOT NULL,

            target_id TEXT NOT NULL,

            relationship TEXT NOT NULL,

            weight REAL DEFAULT 1,

            risk_contribution REAL DEFAULT 0,

            metadata TEXT,

            first_seen TIMESTAMP,

            last_seen TIMESTAMP,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(source_id, target_id, relationship)
        )
    """)

    # --------------------------------------------------------
    # DIGITAL TWIN VULNERABILITIES
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS digital_twin_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            tenant_id TEXT,

            asset_id TEXT NOT NULL,

            vulnerability_id TEXT,

            name TEXT,

            description TEXT,

            severity TEXT,

            cvss_score REAL DEFAULT 0,

            exploitable INTEGER DEFAULT 0,

            status TEXT DEFAULT 'open',

            first_seen TIMESTAMP,

            last_seen TIMESTAMP,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # DIGITAL TWIN SECURITY CONTROLS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS digital_twin_controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            tenant_id TEXT,

            asset_id TEXT NOT NULL,

            control_type TEXT NOT NULL,

            name TEXT NOT NULL,

            status TEXT DEFAULT 'active',

            effectiveness REAL DEFAULT 0,

            last_verified TIMESTAMP,

            metadata TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # INDEXES
    # --------------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dt_assets_tenant
        ON digital_twin_assets(tenant_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dt_assets_type
        ON digital_twin_assets(asset_type)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dt_relationships_source
        ON digital_twin_relationships(source_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dt_relationships_target
        ON digital_twin_relationships(target_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dt_vulnerabilities_asset
        ON digital_twin_vulnerabilities(asset_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dt_controls_asset
        ON digital_twin_controls(asset_id)
    """)

    conn.commit()
    conn.close()

    print("✅ DIGITAL TWIN DATABASE READY")


# ============================================================
# ASSET MANAGEMENT
# ============================================================

def upsert_asset(
    asset_id,
    asset_type,
    name,
    tenant_id=None,
    description=None,
    status="active",
    criticality=0,
    exposure=0,
    risk_score=0,
    owner=None,
    location=None,
    os=None,
    ip_address=None,
    hostname=None,
    metadata=None,
):
    if not asset_id:
        return None

    asset_type = str(asset_type).upper()

    if asset_type not in ASSET_TYPES:
        raise ValueError(
            f"Unsupported Digital Twin asset type: {asset_type}"
        )

    now = datetime.utcnow().isoformat()

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO digital_twin_assets (
            id,
            tenant_id,
            asset_type,
            name,
            description,
            status,
            criticality,
            exposure,
            risk_score,
            owner,
            location,
            os,
            ip_address,
            hostname,
            first_seen,
            last_seen,
            metadata,
            updated_at
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?
        )

        ON CONFLICT(id)
        DO UPDATE SET

            tenant_id = COALESCE(
                excluded.tenant_id,
                digital_twin_assets.tenant_id
            ),

            asset_type = excluded.asset_type,

            name = COALESCE(
                excluded.name,
                digital_twin_assets.name
            ),

            description = COALESCE(
                excluded.description,
                digital_twin_assets.description
            ),

            status = COALESCE(
                excluded.status,
                digital_twin_assets.status
            ),

            criticality = excluded.criticality,

            exposure = excluded.exposure,

            risk_score = excluded.risk_score,

            owner = COALESCE(
                excluded.owner,
                digital_twin_assets.owner
            ),

            location = COALESCE(
                excluded.location,
                digital_twin_assets.location
            ),

            os = COALESCE(
                excluded.os,
                digital_twin_assets.os
            ),

            ip_address = COALESCE(
                excluded.ip_address,
                digital_twin_assets.ip_address
            ),

            hostname = COALESCE(
                excluded.hostname,
                digital_twin_assets.hostname
            ),

            last_seen = excluded.last_seen,

            metadata = COALESCE(
                excluded.metadata,
                digital_twin_assets.metadata
            ),

            updated_at = CURRENT_TIMESTAMP
    """, (
        str(asset_id),
        tenant_id,
        asset_type,
        name,
        description,
        status,
        float(criticality or 0),
        float(exposure or 0),
        float(risk_score or 0),
        owner,
        location,
        os,
        ip_address,
        hostname,
        now,
        now,
        metadata,
        now,
    ))

    conn.commit()

    cursor.execute("""
        SELECT *
        FROM digital_twin_assets
        WHERE id = ?
    """, (str(asset_id),))

    row = cursor.fetchone()

    conn.close()

    return dict(row) if row else None


# ============================================================
# RELATIONSHIP MANAGEMENT
# ============================================================

def upsert_relationship(
    source_id,
    target_id,
    relationship,
    tenant_id=None,
    weight=1,
    risk_contribution=0,
    metadata=None,
):
    if not source_id or not target_id:
        return None

    if str(source_id) == str(target_id):
        return None

    now = datetime.utcnow().isoformat()

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO digital_twin_relationships (
            tenant_id,
            source_id,
            target_id,
            relationship,
            weight,
            risk_contribution,
            metadata,
            first_seen,
            last_seen,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(
            source_id,
            target_id,
            relationship
        )
        DO UPDATE SET

            weight = digital_twin_relationships.weight + excluded.weight,

            risk_contribution =
                MAX(
                    digital_twin_relationships.risk_contribution,
                    excluded.risk_contribution
                ),

            metadata = COALESCE(
                excluded.metadata,
                digital_twin_relationships.metadata
            ),

            last_seen = excluded.last_seen,

            updated_at = CURRENT_TIMESTAMP
    """, (
        tenant_id,
        str(source_id),
        str(target_id),
        relationship,
        float(weight or 1),
        float(risk_contribution or 0),
        metadata,
        now,
        now,
        now,
    ))

    conn.commit()
    conn.close()


# ============================================================
# EVENT → DIGITAL TWIN
# ============================================================

def ingest_event(event):
    """
    Convert an existing SafeChat AI event into Digital Twin assets
    and relationships.

    USER
       ↓ OWNS / USES
    DEVICE
       ↓ HAS_IP
    IP
       ↓ TARGETED_BY
    THREAT
       ↓ ASSOCIATED_WITH
    INCIDENT
    """

    tenant_id = event.get("tenant_id", "demo")

    username = event.get("username")
    hostname = event.get("hostname")
    source_ip = event.get("source_ip")

    category = event.get(
        "category",
        "Unknown Threat"
    )

    score = float(
        event.get("score", 0) or 0
    )

    correlation_id = event.get(
        "correlation_id"
    )

    if username:
        upsert_asset(
            asset_id=f"user:{username}",
            asset_type="USER",
            name=username,
            tenant_id=tenant_id,
            owner=username,
            risk_score=score,
            status="active",
        )

    if hostname:
        upsert_asset(
            asset_id=f"device:{hostname}",
            asset_type="DEVICE",
            name=hostname,
            tenant_id=tenant_id,
            hostname=hostname,
            risk_score=score,
            status="active",
        )

    if source_ip:
        upsert_asset(
            asset_id=f"ip:{source_ip}",
            asset_type="NETWORK",
            name=source_ip,
            tenant_id=tenant_id,
            ip_address=source_ip,
            exposure=min(score, 100),
            risk_score=score,
            status="active",
        )

    threat_id = f"threat:{category}"

    upsert_asset(
        asset_id=threat_id,
        asset_type="THREAT",
        name=category,
        tenant_id=tenant_id,
        risk_score=score,
        status="active",
    )

    # --------------------------------------------------------
    # USER → DEVICE
    # --------------------------------------------------------

    if username and hostname:
        upsert_relationship(
            source_id=f"user:{username}",
            target_id=f"device:{hostname}",
            relationship="USES",
            tenant_id=tenant_id,
        )

    # --------------------------------------------------------
    # DEVICE → IP
    # --------------------------------------------------------

    if hostname and source_ip:
        upsert_relationship(
            source_id=f"device:{hostname}",
            target_id=f"ip:{source_ip}",
            relationship="HAS_IP",
            tenant_id=tenant_id,
        )

    # --------------------------------------------------------
    # DEVICE → THREAT
    # --------------------------------------------------------

    if hostname:
        upsert_relationship(
            source_id=f"device:{hostname}",
            target_id=threat_id,
            relationship="TARGETED_BY",
            tenant_id=tenant_id,
            risk_contribution=score,
        )

    # --------------------------------------------------------
    # IP → THREAT
    # --------------------------------------------------------

    if source_ip:
        upsert_relationship(
            source_id=f"ip:{source_ip}",
            target_id=threat_id,
            relationship="ASSOCIATED_WITH",
            tenant_id=tenant_id,
            risk_contribution=score,
        )

    # --------------------------------------------------------
    # INCIDENT
    # --------------------------------------------------------

    if correlation_id:

        incident_id = f"incident:{correlation_id}"

        upsert_asset(
            asset_id=incident_id,
            asset_type="INCIDENT",
            name=correlation_id,
            tenant_id=tenant_id,
            risk_score=score,
            status="active",
        )

        if hostname:
            upsert_relationship(
                source_id=incident_id,
                target_id=f"device:{hostname}",
                relationship="AFFECTS",
                tenant_id=tenant_id,
                risk_contribution=score,
            )

        upsert_relationship(
            source_id=incident_id,
            target_id=threat_id,
            relationship="CAUSED_BY",
            tenant_id=tenant_id,
            risk_contribution=score,
        )

    return get_asset_graph(tenant_id)


# ============================================================
# ASSET GRAPH
# ============================================================

def get_asset_graph(tenant_id=None):

    conn = get_conn()
    cursor = conn.cursor()

    if tenant_id:
        cursor.execute("""
            SELECT *
            FROM digital_twin_assets
            WHERE tenant_id = ?
            ORDER BY updated_at DESC
        """, (tenant_id,))
    else:
        cursor.execute("""
            SELECT *
            FROM digital_twin_assets
            ORDER BY updated_at DESC
        """)

    assets = [
        dict(row)
        for row in cursor.fetchall()
    ]

    if tenant_id:
        cursor.execute("""
            SELECT *
            FROM digital_twin_relationships
            WHERE tenant_id = ?
            ORDER BY id ASC
        """, (tenant_id,))
    else:
        cursor.execute("""
            SELECT *
            FROM digital_twin_relationships
            ORDER BY id ASC
        """)

    relationships = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return {
        "assets": assets,
        "relationships": relationships,
    }


# ============================================================
# SINGLE ASSET
# ============================================================

def get_asset(asset_id):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM digital_twin_assets
        WHERE id = ?
    """, (str(asset_id),))

    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    asset = dict(row)

    cursor.execute("""
        SELECT *
        FROM digital_twin_relationships
        WHERE source_id = ?
           OR target_id = ?
        ORDER BY id ASC
    """, (
        str(asset_id),
        str(asset_id),
    ))

    relationships = [
        dict(r)
        for r in cursor.fetchall()
    ]

    cursor.execute("""
        SELECT *
        FROM digital_twin_controls
        WHERE asset_id = ?
        ORDER BY id DESC
    """, (str(asset_id),))

    controls = [
        dict(r)
        for r in cursor.fetchall()
    ]

    cursor.execute("""
        SELECT *
        FROM digital_twin_controls
        WHERE asset_id = ?
        ORDER BY id DESC
    """, (str(asset_id),))

    controls = [
        dict(r)
        for r in cursor.fetchall()
    ]

    conn.close()

    asset["relationships"] = relationships
    asset["vulnerabilities"] = vulnerabilities
    asset["security_controls"] = controls

    return asset


# ============================================================
# DIGITAL TWIN SUMMARY
# ============================================================

def get_digital_twin_summary(tenant_id=None):

    conn = get_conn()
    cursor = conn.cursor()

    if tenant_id:

        cursor.execute("""
            SELECT asset_type, COUNT(*) AS count
            FROM digital_twin_assets
            WHERE tenant_id = ?
            GROUP BY asset_type
        """, (tenant_id,))

    else:

        cursor.execute("""
            SELECT asset_type, COUNT(*) AS count
            FROM digital_twin_assets
            GROUP BY asset_type
        """)

    asset_counts = {
        row["asset_type"]: row["count"]
        for row in cursor.fetchall()
    }

    if tenant_id:

        cursor.execute("""
            SELECT COUNT(*)
            FROM digital_twin_relationships
            WHERE tenant_id = ?
        """, (tenant_id,))

    else:

        cursor.execute("""
            SELECT COUNT(*)
            FROM digital_twin_relationships
        """)

    relationship_count = cursor.fetchone()[0]

    if tenant_id:

        cursor.execute("""
            SELECT
                COALESCE(AVG(risk_score), 0),
                COALESCE(MAX(risk_score), 0)
            FROM digital_twin_assets
            WHERE tenant_id = ?
        """, (tenant_id,))

    else:

        cursor.execute("""
            SELECT
                COALESCE(AVG(risk_score), 0),
                COALESCE(MAX(risk_score), 0)
            FROM digital_twin_assets
        """)

    avg_risk, max_risk = cursor.fetchone()

    conn.close()

    return {
        "assets": sum(asset_counts.values()),
        "relationships": relationship_count,
        "asset_types": asset_counts,
        "average_risk": round(float(avg_risk or 0), 2),
        "maximum_risk": round(float(max_risk or 0), 2),
    }


# ============================================================
# INITIALIZE
# ============================================================

init_digital_twin_db()
# ============================================================
# DIGITAL TWIN — ASSET RISK INTELLIGENCE
# ============================================================

def calculate_asset_risk(asset_id):
    """
    Calculate enterprise asset risk using:

        Base Threat Risk
        + Criticality
        + Exposure
        + Vulnerabilities
        - Security Controls

    Final score is normalized to 0–100.
    """

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM digital_twin_assets
        WHERE id = ?
    """, (str(asset_id),))

    asset = cursor.fetchone()

    if not asset:
        conn.close()
        return None

    asset = dict(asset)

    base_risk = float(asset.get("risk_score") or 0)
    criticality = float(asset.get("criticality") or 0)
    exposure = float(asset.get("exposure") or 0)

    # --------------------------------------------------------
    # VULNERABILITY RISK
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            COALESCE(SUM(cvss_score), 0),
            COUNT(*),
            COALESCE(SUM(
                CASE
                    WHEN exploitable = 1 THEN 20
                    ELSE 0
                END
            ), 0)
        FROM digital_twin_vulnerabilities
        WHERE asset_id = ?
          AND status = 'open'
    """, (str(asset_id),))

    vulnerability_score, vulnerability_count, exploit_bonus = (
        cursor.fetchone()
    )

    vulnerability_score = min(
        float(vulnerability_score or 0),
        100
    )

    vulnerability_count = int(
        vulnerability_count or 0
    )

    exploit_bonus = min(
        float(exploit_bonus or 0),
        40
    )

    # --------------------------------------------------------
    # SECURITY CONTROL EFFECTIVENESS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            COALESCE(AVG(effectiveness), 0),
            COUNT(*)
        FROM digital_twin_controls
        WHERE asset_id = ?
          AND status = 'active'
    """, (str(asset_id),))

    control_effectiveness, control_count = cursor.fetchone()

    control_effectiveness = min(
        max(float(control_effectiveness or 0), 0),
        100
    )

    control_count = int(control_count or 0)

    # --------------------------------------------------------
    # RELATIONSHIP RISK
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            COALESCE(SUM(risk_contribution), 0)
        FROM digital_twin_relationships
        WHERE source_id = ?
           OR target_id = ?
    """, (
        str(asset_id),
        str(asset_id)
    ))

    relationship_risk = float(
        cursor.fetchone()[0] or 0
    )

    relationship_risk = min(
        relationship_risk,
        100
    )

    # --------------------------------------------------------
    # RISK MODEL
    # --------------------------------------------------------

        # --------------------------------------------------------
    # RISK MODEL
    # --------------------------------------------------------
    #
    # Threat/base risk is the strongest signal.
    # Environmental factors increase or decrease it.
    #

    weighted_base = base_risk * 0.50

    weighted_criticality = criticality * 0.15

    weighted_exposure = exposure * 0.15

    weighted_vulnerability = vulnerability_score * 0.10

    weighted_relationship = relationship_risk * 0.10

    raw_risk = (
        weighted_base
        + weighted_criticality
        + weighted_exposure
        + weighted_vulnerability
        + weighted_relationship
        + exploit_bonus
    )

    # Security controls reduce overall risk.

    control_reduction = (
        control_effectiveness / 100
    ) * 25

    final_risk = raw_risk - control_reduction

    final_risk = max(
        0,
        min(100, final_risk)
    )

    # --------------------------------------------------------
    # RISK STATUS
    # --------------------------------------------------------

    if final_risk >= 90:
        risk_status = "CRITICAL"

    elif final_risk >= 75:
        risk_status = "HIGH"

    elif final_risk >= 50:
        risk_status = "MEDIUM"

    elif final_risk >= 25:
        risk_status = "LOW"

    else:
        risk_status = "MINIMAL"

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    cursor.execute("""
        UPDATE digital_twin_assets
        SET
            risk_score = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        round(final_risk, 2),
        str(asset_id)
    ))

    conn.commit()
    conn.close()

    return {
        "asset_id": str(asset_id),
        "risk_score": round(final_risk, 2),
        "risk_status": risk_status,
        "base_risk": round(base_risk, 2),
        "criticality": round(criticality, 2),
        "exposure": round(exposure, 2),
        "vulnerability_score": round(
            vulnerability_score,
            2
        ),
        "vulnerability_count": vulnerability_count,
        "exploit_bonus": round(
            exploit_bonus,
            2
        ),
        "relationship_risk": round(
            relationship_risk,
            2
        ),
        "control_effectiveness": round(
            control_effectiveness,
            2
        ),
        "control_count": control_count,
    }


def recalculate_all_asset_risks(tenant_id=None):
    """
    Recalculate risk for every Digital Twin asset.
    """

    conn = get_conn()
    cursor = conn.cursor()

    if tenant_id:

        cursor.execute("""
            SELECT id
            FROM digital_twin_assets
            WHERE tenant_id = ?
        """, (tenant_id,))

    else:

        cursor.execute("""
            SELECT id
            FROM digital_twin_assets
        """)

    asset_ids = [
        row["id"]
        for row in cursor.fetchall()
    ]

    conn.close()

    results = []

    for asset_id in asset_ids:

        result = calculate_asset_risk(asset_id)

        if result:
            results.append(result)

    return results


def get_high_risk_assets(
    tenant_id=None,
    minimum_score=75
):
    """
    Return assets requiring SOC attention.
    """

    conn = get_conn()
    cursor = conn.cursor()

    if tenant_id:

        cursor.execute("""
            SELECT *
            FROM digital_twin_assets
            WHERE tenant_id = ?
              AND risk_score >= ?
            ORDER BY risk_score DESC
        """, (
            tenant_id,
            minimum_score
        ))

    else:

        cursor.execute("""
            SELECT *
            FROM digital_twin_assets
            WHERE risk_score >= ?
            ORDER BY risk_score DESC
        """, (
            minimum_score,
        ))

    assets = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return assets


def get_asset_risk_summary(tenant_id=None):
    """
    Enterprise-wide Digital Twin risk intelligence.
    """

    conn = get_conn()
    cursor = conn.cursor()

    if tenant_id:

        cursor.execute("""
            SELECT
                COUNT(*) AS total,
                COALESCE(AVG(risk_score), 0) AS average,
                COALESCE(MAX(risk_score), 0) AS maximum,

                SUM(
                    CASE
                        WHEN risk_score >= 90
                        THEN 1 ELSE 0
                    END
                ) AS critical,

                SUM(
                    CASE
                        WHEN risk_score >= 75
                         AND risk_score < 90
                        THEN 1 ELSE 0
                    END
                ) AS high,

                SUM(
                    CASE
                        WHEN risk_score >= 50
                         AND risk_score < 75
                        THEN 1 ELSE 0
                    END
                ) AS medium

            FROM digital_twin_assets
            WHERE tenant_id = ?
        """, (tenant_id,))

    else:

        cursor.execute("""
            SELECT
                COUNT(*) AS total,
                COALESCE(AVG(risk_score), 0) AS average,
                COALESCE(MAX(risk_score), 0) AS maximum,

                SUM(
                    CASE
                        WHEN risk_score >= 90
                        THEN 1 ELSE 0
                    END
                ) AS critical,

                SUM(
                    CASE
                        WHEN risk_score >= 75
                         AND risk_score < 90
                        THEN 1 ELSE 0
                    END
                ) AS high,

                SUM(
                    CASE
                        WHEN risk_score >= 50
                         AND risk_score < 75
                        THEN 1 ELSE 0
                    END
                ) AS medium

            FROM digital_twin_assets
        """)

    row = cursor.fetchone()

    conn.close()

    return {
        "total_assets": int(row["total"] or 0),
        "average_risk": round(
            float(row["average"] or 0),
            2
        ),
        "maximum_risk": round(
            float(row["maximum"] or 0),
            2
        ),
        "critical_assets": int(
            row["critical"] or 0
        ),
        "high_risk_assets": int(
            row["high"] or 0
        ),
        "medium_risk_assets": int(
            row["medium"] or 0
        ),
    }