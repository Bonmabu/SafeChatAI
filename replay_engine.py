from datetime import datetime

REPLAY = []


def add_replay_event(event):

    print("========== REPLAY ==========")
    print(event)

    REPLAY.append({
        "time": datetime.utcnow().isoformat(),
        "category": event.get("category"),
        "score": event.get("score"),
        "stage": event.get("stage"),
        "mitre": event.get("mitre"),
        "source_ip": event.get("source_ip"),
        "hostname": event.get("hostname"),
        "username": event.get("username")
    })

    print("REPLAY SIZE =", len(REPLAY))


def get_replay():
    return REPLAY


def clear_replay():
    REPLAY.clear()