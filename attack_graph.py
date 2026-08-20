import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "SafeChatAI.db")
)


def get_conn():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_attack_graph_db():
    conn = get_conn()
    cursor = conn.cursor()

    # ---------------------------------------
    # ATTACK GRAPH NODES
    # ---------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_graph_nodes (
    id TEXT PRIMARY KEY,
    node_type TEXT,
    category TEXT,
    score REAL DEFAULT 0,
    max_score REAL DEFAULT 0,
    stage TEXT,
    mitre TEXT,
    count INTEGER DEFAULT 1,

    tenant_id TEXT,

    name TEXT,
    description TEXT,

    status TEXT DEFAULT 'active',

    criticality REAL DEFAULT 0,
    exposure REAL DEFAULT 0,

    owner TEXT,
    location TEXT,

    os TEXT,
    ip_address TEXT,
    hostname TEXT,

    risk_score REAL DEFAULT 0,

    first_seen TIMESTAMP,
    last_seen TIMESTAMP,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
    """)

    # ---------------------------------------
    # MIGRATE EXISTING NODE TABLE
    # ---------------------------------------
    cursor.execute("PRAGMA table_info(attack_graph_nodes)")
    node_columns = {
        row["name"]
        for row in cursor.fetchall()
    }

    migrations = {
        "node_type":
            "ALTER TABLE attack_graph_nodes ADD COLUMN node_type TEXT",

        "category":
            "ALTER TABLE attack_graph_nodes ADD COLUMN category TEXT",

        "score":
            "ALTER TABLE attack_graph_nodes ADD COLUMN score REAL DEFAULT 0",

        "max_score":
            "ALTER TABLE attack_graph_nodes ADD COLUMN max_score REAL DEFAULT 0",

        "stage":
            "ALTER TABLE attack_graph_nodes ADD COLUMN stage TEXT",

        "mitre":
            "ALTER TABLE attack_graph_nodes ADD COLUMN mitre TEXT",

        "count":
            "ALTER TABLE attack_graph_nodes ADD COLUMN count INTEGER DEFAULT 1",

        "tenant_id":
            "ALTER TABLE attack_graph_nodes ADD COLUMN tenant_id TEXT",

        "name":
            "ALTER TABLE attack_graph_nodes ADD COLUMN name TEXT",

        "description":
            "ALTER TABLE attack_graph_nodes ADD COLUMN description TEXT",

        "status":
            "ALTER TABLE attack_graph_nodes ADD COLUMN status TEXT DEFAULT 'active'",

        "criticality":
            "ALTER TABLE attack_graph_nodes ADD COLUMN criticality REAL DEFAULT 0",

        "exposure":
            "ALTER TABLE attack_graph_nodes ADD COLUMN exposure REAL DEFAULT 0",

        "owner":
            "ALTER TABLE attack_graph_nodes ADD COLUMN owner TEXT",

        "location":
            "ALTER TABLE attack_graph_nodes ADD COLUMN location TEXT",

        "os":
            "ALTER TABLE attack_graph_nodes ADD COLUMN os TEXT",

        "ip_address":
            "ALTER TABLE attack_graph_nodes ADD COLUMN ip_address TEXT",

        "hostname":
            "ALTER TABLE attack_graph_nodes ADD COLUMN hostname TEXT",

        "risk_score":
            "ALTER TABLE attack_graph_nodes ADD COLUMN risk_score REAL DEFAULT 0",

        "first_seen":
            "ALTER TABLE attack_graph_nodes ADD COLUMN first_seen TIMESTAMP",

        "last_seen":
            "ALTER TABLE attack_graph_nodes ADD COLUMN last_seen TIMESTAMP",

        "updated_at":
            "ALTER TABLE attack_graph_nodes ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    }

    for column, sql in migrations.items():
        if column not in node_columns:
            print(f"🔧 Adding attack_graph_nodes.{column}")
            cursor.execute(sql)

    # ---------------------------------------
    # ATTACK GRAPH EDGES
    # ---------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_graph_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            relationship TEXT DEFAULT 'CORRELATED_ATTACK',
            category TEXT DEFAULT 'CORRELATED_ATTACK',
            weight INTEGER DEFAULT 1,
            timestamp TEXT,
            UNIQUE(source, target)
        )
    """)

    # ---------------------------------------
    # MIGRATE EXISTING EDGE TABLE
    # ---------------------------------------
    cursor.execute("PRAGMA table_info(attack_graph_edges)")
    edge_columns = {
        row["name"]
        for row in cursor.fetchall()
    }

    edge_migrations = {
        "relationship":
            "ALTER TABLE attack_graph_edges ADD COLUMN relationship TEXT DEFAULT 'CORRELATED_ATTACK'",

        "category":
            "ALTER TABLE attack_graph_edges ADD COLUMN category TEXT DEFAULT 'CORRELATED_ATTACK'",

        "weight":
            "ALTER TABLE attack_graph_edges ADD COLUMN weight INTEGER DEFAULT 1",

        "timestamp":
            "ALTER TABLE attack_graph_edges ADD COLUMN timestamp TEXT"
    }

    for column, sql in edge_migrations.items():
        if column not in edge_columns:
            print(f"🔧 Adding attack_graph_edges.{column}")
            cursor.execute(sql)

    conn.commit()

    # ---------------------------------------
    # VERIFY SCHEMA
    # ---------------------------------------
    cursor.execute("PRAGMA table_info(attack_graph_nodes)")
    verified_nodes = {
        row["name"]
        for row in cursor.fetchall()
    }

    cursor.execute("PRAGMA table_info(attack_graph_edges)")
    verified_edges = {
        row["name"]
        for row in cursor.fetchall()
    }

    required_nodes = {
        "id",
        "node_type",
        "category",
        "score",
        "max_score",
        "stage",
        "mitre",
        "count",
        "updated_at"
    }

    required_edges = {
        "source",
        "target",
        "relationship",
        "category",
        "weight",
        "timestamp"
    }

    missing_nodes = required_nodes - verified_nodes
    missing_edges = required_edges - verified_edges

    if missing_nodes:
        print("❌ ATTACK GRAPH NODE SCHEMA MISSING:", missing_nodes)
    else:
        print("✅ ATTACK GRAPH NODES SCHEMA OK")

    if missing_edges:
        print("❌ ATTACK GRAPH EDGE SCHEMA MISSING:", missing_edges)
    else:
        print("✅ ATTACK GRAPH EDGES SCHEMA OK")

    conn.close()


def save_node(node):
    """
    Persist an Attack Graph / Digital Twin node.

    The existing attack graph fields remain compatible while
    Digital Twin metadata is stored when available.
    """

    conn = get_conn()
    cursor = conn.cursor()

    node_id = node.get("id")

    if not node_id:
        conn.close()
        return

    node_type = node.get(
        "node_type",
        node.get("type")
    )

    now = node.get("updated_at")

    cursor.execute("""
        INSERT INTO attack_graph_nodes (
            id,
            node_type,
            category,
            score,
            max_score,
            stage,
            mitre,
            count,

            tenant_id,
            name,
            description,
            status,
            criticality,
            exposure,
            owner,
            location,
            os,
            ip_address,
            hostname,
            risk_score,
            first_seen,
            last_seen,
            updated_at
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?
        )
        ON CONFLICT(id)
        DO UPDATE SET
            node_type = COALESCE(excluded.node_type,
                                 attack_graph_nodes.node_type),

            category = COALESCE(excluded.category,
                                attack_graph_nodes.category),

            score = excluded.score,

            max_score = CASE
                WHEN excluded.max_score > attack_graph_nodes.max_score
                THEN excluded.max_score
                ELSE attack_graph_nodes.max_score
            END,

            stage = COALESCE(excluded.stage,
                             attack_graph_nodes.stage),

            mitre = COALESCE(excluded.mitre,
                             attack_graph_nodes.mitre),

            count = excluded.count,

            tenant_id = COALESCE(excluded.tenant_id,
                                 attack_graph_nodes.tenant_id),

            name = COALESCE(excluded.name,
                            attack_graph_nodes.name),

            description = COALESCE(excluded.description,
                                   attack_graph_nodes.description),

            status = COALESCE(excluded.status,
                              attack_graph_nodes.status),

            criticality = COALESCE(excluded.criticality,
                                   attack_graph_nodes.criticality),

            exposure = COALESCE(excluded.exposure,
                                attack_graph_nodes.exposure),

            owner = COALESCE(excluded.owner,
                             attack_graph_nodes.owner),

            location = COALESCE(excluded.location,
                                attack_graph_nodes.location),

            os = COALESCE(excluded.os,
                          attack_graph_nodes.os),

            ip_address = COALESCE(excluded.ip_address,
                                  attack_graph_nodes.ip_address),

            hostname = COALESCE(excluded.hostname,
                                attack_graph_nodes.hostname),

            risk_score = COALESCE(excluded.risk_score,
                                  attack_graph_nodes.risk_score),

            first_seen = COALESCE(
                attack_graph_nodes.first_seen,
                excluded.first_seen
            ),

            last_seen = COALESCE(
                excluded.last_seen,
                attack_graph_nodes.last_seen
            ),

            updated_at = CURRENT_TIMESTAMP
    """, (
        node_id,
        node_type,
        node.get("category"),
        node.get("score", 0),
        node.get("max_score", node.get("score", 0)),
        node.get("stage"),
        node.get("mitre"),
        node.get("count", 1),

        node.get("tenant_id"),

        node.get(
            "name",
            str(node_id)
        ),

        node.get("description"),

        node.get(
            "status",
            "active"
        ),

        node.get(
            "criticality",
            0
        ),

        node.get(
            "exposure",
            0
        ),

        node.get("owner"),
        node.get("location"),

        node.get("os"),

        node.get("ip_address"),

        node.get("hostname"),

        node.get(
            "risk_score",
            node.get("score", 0)
        ),

        node.get("first_seen", now),
        node.get("last_seen", now),

        now
    ))

    conn.commit()
    conn.close()
def save_edge(edge):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, weight
        FROM attack_graph_edges
        WHERE source = ? AND target = ?
    """, (
        edge.get("source"),
        edge.get("target")
    ))

    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE attack_graph_edges
            SET
                weight = ?,
                relationship = ?,
                category = ?,
                timestamp = ?
            WHERE id = ?
        """, (
            edge.get("weight", 1),
            edge.get("relationship", "CORRELATED_ATTACK"),
            edge.get("category", "CORRELATED_ATTACK"),
            edge.get("timestamp"),
            existing["id"]
        ))
    else:
        cursor.execute("""
            INSERT INTO attack_graph_edges (
                source,
                target,
                relationship,
                category,
                weight,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            edge.get("source"),
            edge.get("target"),
            edge.get("relationship", "CORRELATED_ATTACK"),
            edge.get("category", "CORRELATED_ATTACK"),
            edge.get("weight", 1),
            edge.get("timestamp")
        ))

    conn.commit()
    conn.close()


def add_event(event):
    source = event.get("source_ip", "Unknown IP")
    user = event.get("username", "Unknown User")
    host = event.get("hostname", "Unknown Host")
    category = event.get("category", "Unknown Threat")
    stage = event.get("stage", "Initial Access")
    campaign = event.get("campaign", "Unknown Campaign")

    nodes = [
        (source, "ip"),
        (user, "user"),
        (host, "host"),
        (category, "threat"),
        (stage, "mitre_stage"),
        (campaign, "campaign")
    ]

    for node_id, node_type in nodes:

        node = {
            "id": node_id,
            "type": node_type,
            "category": category,
            "count": 1
        }

        save_node(node)

    edges = [
        (source, user),
        (user, host),
        (host, category),
        (category, stage),
        (stage, campaign)
    ]

    for source_id, target_id in edges:
        save_edge({
            "source": source_id,
            "target": target_id,
            "relationship": "CORRELATED_ATTACK",
            "category": category,
            "weight": 1
        })


def get_graph():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            node_type,
            category,
            score,
            max_score,
            stage,
            mitre,
            count
        FROM attack_graph_nodes
        ORDER BY updated_at ASC
    """)

    node_rows = cursor.fetchall()

    cursor.execute("""
        SELECT
            source,
            target,
            relationship,
            category,
            weight,
            timestamp
        FROM attack_graph_edges
        ORDER BY id ASC
    """)

    edge_rows = cursor.fetchall()

    conn.close()

    nodes = []

    for row in node_rows:
        nodes.append({
            "id": row["id"],
            "type": row["node_type"],
            "category": row["category"],
            "score": row["score"],
            "max_score": row["max_score"],
            "stage": row["stage"],
            "mitre": row["mitre"],
            "count": row["count"]
        })

    edges = [dict(row) for row in edge_rows]

    return {
        "nodes": nodes,
        "edges": edges
    }


def clear_graph():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM attack_graph_edges")
    cursor.execute("DELETE FROM attack_graph_nodes")

    conn.commit()
    conn.close()


init_attack_graph_db()