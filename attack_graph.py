from collections import defaultdict

GRAPH = {
    "nodes": {},
    "edges": []
}


def add_event(event):

    source = event.get("source_ip", "Unknown IP")
    user = event.get("username", "Unknown User")
    host = event.get("hostname", "Unknown Host")
    category = event.get("category", "Unknown Threat")
    stage = event.get("stage", "Initial Access")
    campaign = event.get("campaign", "Unknown Campaign")

    for node_id, node_type in [
        (source, "ip"),
        (user, "user"),
        (host, "host"),
        (category, "threat"),
        (stage, "mitre_stage"),
        (campaign, "campaign")
    ]:

        if node_id not in GRAPH["nodes"]:
            GRAPH["nodes"][node_id] = {
                "id": node_id,
                "type": node_type,
                "count": 1
            }
        else:
            GRAPH["nodes"][node_id]["count"] += 1

    GRAPH["edges"].append({
        "source": source,
        "target": user
    })

    GRAPH["edges"].append({
        "source": user,
        "target": host
    })

    GRAPH["edges"].append({
        "source": host,
        "target": category
    })

    GRAPH["edges"].append({
        "source": category,
        "target": stage
    })

    GRAPH["edges"].append({
        "source": stage,
        "target": campaign
    })

def get_graph():

    return {
        "nodes": list(GRAPH["nodes"].values()),
        "edges": GRAPH["edges"]
    }


def clear_graph():

    GRAPH["nodes"].clear()
    GRAPH["edges"].clear()