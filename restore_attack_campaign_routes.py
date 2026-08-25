from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8-sig")

imports = '''from event_correlation import (
    init_event_correlation,
    correlate_event as correlate_fabric_event,
    get_event_correlations,
    get_correlation_cluster,
    get_correlation_clusters,
    get_attack_campaign,
    get_attack_campaigns,
    get_campaign_timeline,
)
from security_fabric import (
    init_security_fabric,
    persist_security_event,
    get_security_events,
    get_security_event,
)
'''

marker = 'from replay_engine import add_replay_event, get_replay'

if 'from event_correlation import (' not in text:
    text = text.replace(marker, imports + marker, 1)

route = '''

@app.get("/attack-campaigns")
def attack_campaigns(
    limit: int = 50,
    tenant_id: str | None = None,
):
    return {
        "campaigns": get_attack_campaigns(
            tenant_id=tenant_id,
            limit=limit,
        )
    }


@app.get("/attack-campaigns/{campaign_id}")
def attack_campaign(campaign_id: str):
    campaign = get_attack_campaign(campaign_id)

    if not campaign:
        return {
            "success": False,
            "error": "CAMPAIGN_NOT_FOUND",
            "campaign_id": campaign_id,
        }

    return {
        "success": True,
        "campaign": campaign,
    }


@app.get("/attack-campaigns/{campaign_id}/investigation")
def attack_campaign_investigation(campaign_id: str):
    campaign = get_attack_campaign(campaign_id)

    if not campaign:
        return {
            "success": False,
            "error": "CAMPAIGN_NOT_FOUND",
            "campaign_id": campaign_id,
        }

    cluster_id = campaign.get("cluster_id")
    cluster = (
        get_correlation_cluster(cluster_id)
        if cluster_id
        else None
    )

    response_events = []

    try:
        correlation_ids = set()

        for member in (cluster or {}).get("members", []):
            event_id = member.get("event_id")

            if not event_id:
                continue

            source_event = get_security_event(event_id)

            if source_event:
                correlation_id = source_event.get("correlation_id")

                if correlation_id:
                    correlation_ids.add(correlation_id)

        fabric_events = get_security_events(
            limit=500,
            tenant_id=campaign.get("tenant_id"),
        )

        for fabric_event in fabric_events:
            if fabric_event.get("event_type") != "auto_response_event":
                continue

            same_campaign = (
                fabric_event.get("campaign_id") == campaign_id
            )

            same_correlation = (
                fabric_event.get("correlation_id")
                in correlation_ids
            )

            if same_campaign or same_correlation:
                response_events.append(fabric_event)

    except Exception as response_error:
        print(
            "[42.22] Campaign response lookup failed:",
            response_error,
        )

    response_status = (
        "EXECUTED"
        if any(
            event.get("status") == "EXECUTED"
            for event in response_events
        )
        else (
            "BACKFILLED"
            if response_events
            else "NO_RESPONSE_RECORDED"
        )
    )

    investigation = {
        "campaign": campaign,
        "cluster": cluster,
        "timeline": get_campaign_timeline(campaign_id),
        "response": {
            "status": response_status,
            "event_count": len(response_events),
            "events": response_events,
        },
        "threat_dna": None,
        "attack_graph": None,
        "digital_twin": None,
        "replay": None,
        "links": {
            "campaign_id": campaign_id,
            "cluster_id": cluster_id,
        },
    }

    return {
        "success": True,
        "investigation": investigation,
    }

'''

if '@app.get("/attack-campaigns")' not in text:
    anchor = '@app.get("/campaigns")'
    if anchor in text:
        text = text.replace(anchor, route + '\n' + anchor, 1)
    else:
        text += route

path.write_text(text, encoding="utf-8", newline="\n")

print("Attack campaign routes/imports restored.")
