from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

marker = '# CUSTOMER DASHBOARD MISSING COMPATIBILITY ROUTES'

if '@app.get("/attack-graph")' in text:
    print("ATTACK GRAPH ROUTE ALREADY EXISTS. No change made.")
    raise SystemExit(0)

route = r'''
# ============================================================
# ATTACK GRAPH COMPATIBILITY ROUTE
# ============================================================

@app.get("/attack-graph")
def attack_graph():
    """
    Return the current live SafeChat AI Attack Graph.

    Uses the existing in-memory ATTACK_GRAPH populated by
    /soc-ai-stream and the existing graph helper functions.
    """
    try:
        graph = ATTACK_GRAPH

        nodes = graph.get("nodes", {})
        edges = graph.get("edges", [])

        if isinstance(nodes, dict):
            nodes = list(nodes.values())

        if not isinstance(nodes, list):
            nodes = []

        if not isinstance(edges, list):
            edges = []

        return {
            "nodes": nodes,
            "edges": edges,
            "links": edges,
            "last_node": graph.get("last_node")
        }

    except Exception as e:
        print("ATTACK GRAPH ERROR:", repr(e))
        return {
            "nodes": [],
            "edges": [],
            "links": [],
            "last_node": None
        }


'''

if marker not in text:
    raise SystemExit("ERROR: compatibility route marker not found")

text = text.replace(marker, route + marker, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: Added GET /attack-graph route.")
