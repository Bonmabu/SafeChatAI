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
'''

new = '''        previous_node = ATTACK_GRAPH.get("last_node")

        graph = add_graph_node(
            node_id=node_id,
            category=category,
            score=score,
            stage=stage,
            mitre=mitre
        )

        # Connect this attack to the previous live attack.
        if previous_node and previous_node != node_id:
'''

if old not in text:
    raise SystemExit("Graph section not found for correction.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("Attack Graph previous-node logic corrected.")

