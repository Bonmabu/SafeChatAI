from pathlib import Path

path = Path("frontend/src/customer/CustomerDashboard.jsx")
text = path.read_text(encoding="utf-8")

start = text.index("async function loadGraph()")
end = text.index("function getAttackStage", start)

new_block = r'''async function loadGraph() {
  try {
    const res = await axios.get(
      `${API}/attack-graph`,
      getAuthConfig()
    );

    const data = res.data || {};

    const nodes = Array.isArray(data.nodes)
      ? data.nodes
      : Object.values(data.nodes || {});

    const rawLinks = Array.isArray(data.links)
      ? data.links
      : Array.isArray(data.edges)
      ? data.edges
      : [];

    const nodeIds = new Set(
      nodes
        .filter(Boolean)
        .map((n) => String(n.id))
    );

    const links = rawLinks.filter((link) => {
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

    console.log("ATTACK GRAPH API =", data);
    console.log("ATTACK GRAPH NODES =", nodes);
    console.log("ATTACK GRAPH LINKS =", links);

    setGraphData({
      nodes,
      links
    });

    if (nodes.length > 0) {
      const highest = [...nodes].sort(
        (a, b) =>
          Number(b.score ?? b.max_score ?? 0) -
          Number(a.score ?? a.max_score ?? 0)
      )[0];

      setHighestRiskNode(highest);

      const score = Number(
        highest.score ?? highest.max_score ?? 0
      );

      if (score >= 90)
        setCurrentThreatLevel("CRITICAL");
      else if (score >= 75)
        setCurrentThreatLevel("HIGH");
      else if (score >= 50)
        setCurrentThreatLevel("MEDIUM");
      else
        setCurrentThreatLevel("LOW");

      setRootNode(nodes[0]);
    } else {
      setHighestRiskNode(null);
      setRootNode(null);
      setCurrentThreatLevel("LOW");
    }

  } catch (err) {
    console.error(
      "ATTACK GRAPH LOAD ERROR:",
      err.response?.data || err.message
    );

    setGraphData({
      nodes: [],
      links: []
    });
  }
}

'''

text = text[:start] + new_block + text[end:]

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: CustomerDashboard now loads the real /attack-graph API.")
