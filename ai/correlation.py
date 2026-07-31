from collections import defaultdict


def correlate_incidents(nodes, links):

    campaigns = []

    visited = set()

    graph = defaultdict(list)

    for link in links:

        source = link["source"]
        target = link["target"]

        graph[source].append(target)
        graph[target].append(source)

    node_lookup = {
        n["id"]: n
        for n in nodes
    }

    for node in nodes:

        if node["id"] in visited:
            continue

        stack = [node["id"]]

        cluster = []

        highest = node

        while stack:

            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)

            n = node_lookup[current]

            cluster.append(n)

            if n.get("score", 0) > highest.get("score", 0):
                highest = n

            for nxt in graph[current]:
                if nxt not in visited:
                    stack.append(nxt)

        campaigns.append({

            "campaign_id": f"CAM-{len(campaigns)+1:04}",

            "incident_count": len(cluster),

            "highest_risk": highest,

            "patient_zero": cluster[0],

            "nodes": cluster
        })

    return campaigns