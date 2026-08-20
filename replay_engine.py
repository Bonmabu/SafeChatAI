from datetime import datetime
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "scams.db")
)


def get_conn():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_replay_db():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_replay (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT,
            category TEXT,
            score REAL DEFAULT 0,
            stage TEXT,
            mitre TEXT,
            correlation_id TEXT,
            source TEXT,
            target TEXT,
            event_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def add_replay_event(event):

    print("========== REPLAY ==========")
    print(event)

    category = event.get("category")
    score = event.get("score", 0)

    # Do not record harmless heartbeat / Safe events.
    if category == "Safe" and score <= 10:
        print("REPLAY SKIPPED: harmless Safe event")
        return

    replay_event = {
        "time": datetime.utcnow().isoformat(),
        "category": category,
        "score": score,
        "stage": event.get("stage"),
        "mitre": event.get("mitre"),
        "correlation_id": event.get("correlation_id"),
        "source": event.get("source"),
        "target": event.get("target"),
        "event_type": event.get("event_type", "THREAT")
    }

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO attack_replay (
            event_time,
            category,
            score,
            stage,
            mitre,
            correlation_id,
            source,
            target,
            event_type
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        replay_event["time"],
        replay_event["category"],
        replay_event["score"],
        replay_event["stage"],
        replay_event["mitre"],
        replay_event["correlation_id"],
        replay_event["source"],
        replay_event["target"],
        replay_event["event_type"]
    ))

    conn.commit()
    conn.close()

    print("REPLAY EVENT SAVED")


def get_replay(correlation_id=None):

    conn = get_conn()
    cursor = conn.cursor()

    if correlation_id:
        cursor.execute("""
            SELECT
                id,
                event_time AS time,
                category,
                score,
                stage,
                mitre,
                correlation_id,
                source,
                target,
                event_type
            FROM attack_replay
            WHERE correlation_id = ?
            ORDER BY event_time ASC, id ASC
            LIMIT 500
        """, (correlation_id,))
    else:
        cursor.execute("""
            SELECT
                id,
                event_time AS time,
                category,
                score,
                stage,
                mitre,
                correlation_id,
                source,
                target,
                event_type
            FROM attack_replay
            ORDER BY event_time ASC, id ASC
            LIMIT 500
        """)

    rows = cursor.fetchall()
    conn.close()

    replay_events = []

    for row in rows:
        event = dict(row)

        # Extra safety:
        # never allow harmless Safe events into Attack Replay.
        if (
            event.get("category") == "Safe"
            and float(event.get("score") or 0) <= 10
        ):
            continue

        event["source_ip"] = event.get("source") or ""
        event["event_type"] = (
            event.get("event_type") or "THREAT"
        )

        replay_events.append(event)

    return replay_events
def build_replay(correlation_id):

    events = get_replay(correlation_id)

    if not events:
        return {
            "correlation_id": correlation_id,
            "event_count": 0,
            "start_time": None,
            "end_time": None,
            "duration_seconds": 0,
            "risk_score": 0,
            "source": None,
            "target": None,
            "categories": [],
            "stages": [],
            "mitre_techniques": [],
            "events": []
        }

    start_time = events[0]["time"]
    end_time = events[-1]["time"]

    try:
        start_dt = datetime.fromisoformat(start_time)
        end_dt = datetime.fromisoformat(end_time)
        duration_seconds = max(
            0,
            (end_dt - start_dt).total_seconds()
        )
    except Exception:
        duration_seconds = 0

    scores = [
        float(event.get("score") or 0)
        for event in events
    ]

    categories = list(dict.fromkeys(
        event.get("category")
        for event in events
        if event.get("category")
    ))

    stages = list(dict.fromkeys(
        event.get("stage")
        for event in events
        if event.get("stage")
    ))

    mitre_techniques = list(dict.fromkeys(
        event.get("mitre")
        for event in events
        if event.get("mitre")
    ))

    source = next(
        (
            event.get("source")
            for event in events
            if event.get("source")
        ),
        None
    )

    target = next(
        (
            event.get("target")
            for event in events
            if event.get("target")
        ),
        None
    )

    return {
        "correlation_id": correlation_id,
        "event_count": len(events),
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": duration_seconds,
        "risk_score": max(scores) if scores else 0,
        "source": source,
        "target": target,
        "categories": categories,
        "stages": stages,
        "mitre_techniques": mitre_techniques,
        "events": events
    }
def clear_replay():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM attack_replay")

    conn.commit()
    conn.close()


init_replay_db()