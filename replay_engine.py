from datetime import datetime

REPLAY = []


def add_replay_event(event):

    print("========== REPLAY ==========")
    print(event)

    category = event.get("category")
    score = event.get("score", 0)

    # Do not record harmless heartbeat / Safe events.
    # Replay should represent actual security activity.
    if category == "Safe" and score <= 10:
        print("REPLAY SKIPPED: harmless Safe event")
        return

    replay_event = {
        "time": datetime.utcnow().isoformat(),
        "category": category,
        "score": score,
        "stage": event.get("stage"),
        "mitre": event.get("mitre"),
        "source_ip": event.get("source_ip"),
        "hostname": event.get("hostname"),
        "username": event.get("username")
    }

    REPLAY.append(replay_event)

    # Prevent unlimited in-memory growth.
    if len(REPLAY) > 500:
        del REPLAY[:-500]

    print("REPLAY SIZE =", len(REPLAY))


def get_replay():
    return REPLAY


def clear_replay():
    REPLAY.clear()