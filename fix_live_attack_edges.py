from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

old = '''        graph = add_graph_node(
            node_id=node_id,
            category=category,
            score=score,
            stage=stage,
            mitre=mitre
        )

        # Connect this attack to the previous live attack.
        previous_node = graph.get("last_node")

        if previous_node and previous_node != node_id:
            add_graph_edge(
                previous_node,
                node_id,
                category="CORRELATED_ATTACK"
            )
'''

new = '''        # Capture the previous node BEFORE adding the new node.
        previous_node = ATTACK_GRAPH.get("last_node")

        graph = add_graph_node(
            node_id=node_id,
            category=category,
            score=score,
            stage=stage,
            mitre=mitre
        )

        # Connect this attack to the previous live attack.
        if previous_node and previous_node != node_id:
            add_graph_edge(
                previous_node,
                node_id,
                category="CORRELATED_ATTACK"
            )
'''

if old not in text:
    raise SystemExit("ERROR: Expected SOC AI Attack Graph block was not found.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: Fixed live Attack Graph edge creation.")
