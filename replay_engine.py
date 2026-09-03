from datetime import datetime

REPLAY = []


def add_replay_event(event):
    """Record and persist a normalized threat replay event."""

    replay_event = {
        "time": datetime.utcnow().isoformat(),
        "category": event.get("category"),
        "stage": event.get("stage"),
        "source_ip": event.get("source_ip"),
        "hostname": event.get("hostname"),
        "username": event.get("username"),
    }

    REPLAY.append(replay_event)

    try:
        from db import save_replay_event
        save_replay_event(replay_event)
    except Exception as exc:
        print(f"[REPLAY] Persistence warning: {exc}")

    print("========== REPLAY ==========")
    print(replay_event)
    print("REPLAY SIZE =", len(REPLAY))

    return replay_event


def get_replay(tenant_id="demo", limit=500):
    """Return replay events, restoring persisted events when memory is empty."""

    if REPLAY:
        return REPLAY

    try:
        from db import get_replay_events

        persisted = get_replay_events(
            tenant_id=tenant_id,
            limit=limit
        )

        for event in persisted:
            REPLAY.append({
                "time": event.get("time"),
                "category": event.get("category"),
                "stage": event.get("stage"),
                "source_ip": event.get("source_ip"),
                "hostname": event.get("hostname"),
                "username": event.get("username"),
            })

    except Exception as exc:
        print(f"[REPLAY] Restore warning: {exc}")

    return REPLAY


def clear_replay():
    REPLAY.clear()


def get_persisted_replay(tenant_id="demo", limit=500):
    """Return replay events persisted in the database."""

    from db import get_replay_events
    return get_replay_events(
        tenant_id=tenant_id,
        limit=limit
    )


def replay_timeline(tenant_id="demo", limit=500):
    """Return the authoritative persisted threat replay timeline."""

    persisted = get_persisted_replay(
        tenant_id=tenant_id,
        limit=limit
    )

    return {
        "tenant_id": tenant_id,
        "count": len(persisted),
        "timeline": persisted,
        "status": "ready"
    }


def replay_step(index=0, tenant_id="demo", limit=500):
    """Return one deterministic event from the persisted replay timeline."""

    timeline = get_persisted_replay(
        tenant_id=tenant_id,
        limit=limit
    )

    if not timeline:
        return {
            "tenant_id": tenant_id,
            "index": None,
            "count": 0,
            "event": None,
            "has_next": False,
            "has_previous": False,
            "status": "empty"
        }

    index = max(0, min(int(index), len(timeline) - 1))
    event = timeline[index]

    return {
        "tenant_id": tenant_id,
        "index": index,
        "count": len(timeline),
        "event": event,
        "has_next": index < len(timeline) - 1,
        "has_previous": index > 0,
        "status": "ready"
    }
