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

    for node_id, node_type in [
        (source, "ip"),
        (user, "user"),
        (host, "host"),
        (category, "threat")
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
    "target": event["category"]
})

    GRAPH["edges"].append({
    "source": event["category"],
    "target": event["stage"]
})

    GRAPH["edges"].append({
    "source": event["stage"],
    "target": event.get("campaign", "Unknown Campaign")
})


def get_graph():

    return {
        "nodes": list(GRAPH["nodes"].values()),
        "edges": GRAPH["edges"]
    }


def clear_graph():

    GRAPH["nodes"].clear()
    GRAPH["edges"].clear()