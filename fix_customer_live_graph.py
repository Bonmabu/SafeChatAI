from pathlib import Path

path = Path("frontend/src/customer/CustomerDashboard.jsx")
text = path.read_text(encoding="utf-8")

old = '''        case "attack_graph_live":

setGraphData(prev => {
    const nodes = [
        ...prev.nodes.filter(
            n => n.id !== msg.node?.id
        ),
        msg.node
    ].filter(Boolean);


    const links = (msg.links || []).filter(link => {
        if (!link) return false;


        const source =
            typeof link.source === "object"
            ? link.source?.id
            : link.source;


        const target =
            typeof link.target === "object"
            ? link.target?.id
            : link.target;


        if (!source || !target) {
            return false;
        }


        return (
            nodes.some(n => n.id === source) &&
            nodes.some(n => n.id === target)
        );


    });


    return {
        nodes,
        links
    };
});


break;
'''

new = '''        case "attack_graph_live":

          setGraphData((prev) => {
            const incomingNodes = Array.isArray(msg.graph?.nodes)
              ? msg.graph.nodes
              : [];

            const incomingLinks =
              Array.isArray(msg.links)
                ? msg.links
                : Array.isArray(msg.graph?.links)
                ? msg.graph.links
                : [];

            const mergedNodes = [
              ...prev.nodes.filter(
                (n) =>
                  !incomingNodes.some(
                    (incoming) => incoming?.id === n?.id
                  )
              ),
              ...incomingNodes
            ];

            if (msg.node?.id) {
              const index = mergedNodes.findIndex(
                (n) => n.id === msg.node.id
              );

              if (index >= 0) {
                mergedNodes[index] = msg.node;
              } else {
                mergedNodes.push(msg.node);
              }
            }

            const nodeIds = new Set(
              mergedNodes
                .filter(Boolean)
                .map((n) => String(n.id))
            );

            const links = incomingLinks.filter((link) => {
              if (!link) return false;

              const source =
                typeof link.source === "object"
                  ? link.source?.id
                  : link.source;

              const target =
                typeof link.target === "object"
                  ? link.target?.id
                  : link.target;

              return (
                source &&
                target &&
                nodeIds.has(String(source)) &&
                nodeIds.has(String(target))
              );
            });

            console.log(
              "LIVE ATTACK GRAPH:",
              {
                nodes: mergedNodes.length,
                links: links.length
              }
            );

            return {
              nodes: mergedNodes,
              links
            };
          });

          break;
'''

if old not in text:
    raise SystemExit(
        "ERROR: Existing attack_graph_live block was not found."
    )

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: Fixed live Attack Graph WebSocket handling.")
