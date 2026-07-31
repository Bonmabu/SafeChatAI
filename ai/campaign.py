from collections import defaultdict


def detect_campaign(nodes):
    """
    Correlates incidents into an attack campaign.
    """

    if not nodes:
        return {
            "name": "No Campaign",
            "confidence": 0,
            "description": "No incidents available.",
            "root": None,
            "highest": None,
            "incident_count": 0,
            "stages": [],
            "categories": []
        }

    highest = max(nodes, key=lambda n: n.get("score", 0))

    root = min(
        nodes,
        key=lambda n: int(str(n.get("id", "incident-0")).split("-")[-1])
    )

    categories = defaultdict(int)

    for node in nodes:
        categories[node.get("category", "Unknown")] += 1

    dominant = max(categories, key=categories.get)

    confidence = min(
        100,
        50 + len(nodes) * 5 + highest.get("score", 0) / 4
    )

    stages = []

    for node in nodes:
        stage = node.get("stage")

        if stage and stage not in stages:
            stages.append(stage)

    return {
        "name": dominant + " Campaign",
        "confidence": round(confidence, 1),
        "description": f"{len(nodes)} correlated incidents detected.",
        "root": root,
        "highest": highest,
        "incident_count": len(nodes),
        "stages": stages,
        "categories": dict(categories)
    }