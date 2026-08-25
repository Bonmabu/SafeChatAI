import ForceGraph2D from "react-force-graph-2d";

export default function AttackGraph({
  graphRef,
  attackGraph = {},
  activeAttackPath = [],
  highlightNodes = new Set(),
  selectedNode,
  setSelectedNode,
  setSelectedIncident,
  setHighlightNodes,
  setHighlightLinks,
  updateKillChain
}) {
    // Normalize and validate graph data before ForceGraph2D.
  const rawNodes = Array.isArray(attackGraph?.nodes)
    ? attackGraph.nodes
    : Object.values(attackGraph?.nodes || {});

  const rawLinks = Array.isArray(attackGraph?.links)
    ? attackGraph.links
    : Array.isArray(attackGraph?.edges)
      ? attackGraph.edges
      : [];

  const safeNodes = rawNodes.filter((node) => {
    if (!node || node.id === undefined || node.id === null) {
      return false;
    }

    const id = String(node.id).trim();

    return (
      id !== "" &&
      id.toLowerCase() !== "none" &&
      id.toLowerCase() !== "null" &&
      id.toLowerCase() !== "undefined"
    );
  });

  const nodeIds = new Set(
    safeNodes.map((node) => String(node.id).trim())
  );

  const safeLinks = rawLinks.filter((link) => {
    if (!link) {
      return false;
    }

    const source =
      typeof link.source === "object"
        ? link.source?.id
        : link.source;

    const target =
      typeof link.target === "object"
        ? link.target?.id
        : link.target;

    if (
      source === undefined ||
      source === null ||
      target === undefined ||
      target === null
    ) {
      return false;
    }

    const sourceId = String(source).trim();
    const targetId = String(target).trim();

    if (
      !sourceId ||
      !targetId ||
      sourceId.toLowerCase() === "none" ||
      targetId.toLowerCase() === "none" ||
      sourceId.toLowerCase() === "null" ||
      targetId.toLowerCase() === "null" ||
      sourceId.toLowerCase() === "undefined" ||
      targetId.toLowerCase() === "undefined"
    ) {
      return false;
    }

    return (
      nodeIds.has(sourceId) &&
      nodeIds.has(targetId)
    );
  });

  return (
    <>
      <div
        style={{
          height: 500
        }}
      >
        <ForceGraph2D
          ref={graphRef}
          graphData={{
            nodes: safeNodes,
            links: safeLinks
          }}
          width={1200}
          height={650}
          backgroundColor="#111827"
          cooldownTicks={200}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
          
          dagLevelDistance={180}
          nodeRelSize={14}
          linkDirectionalArrowLength={8}
          linkDirectionalArrowRelPos={1}
          linkDirectionalParticles={4}
          linkDirectionalParticleWidth={3}
          nodeLabel={(node) =>
            `${node.category}\nRisk: ${node.max_score ?? node.score ?? 0}`
          }
          linkColor={(link) => {
            const source =
              typeof link.source === "object"
                ? link.source.id
                : link.source;

            const target =
              typeof link.target === "object"
                ? link.target.id
                : link.target;

            const id = `${source}-${target}`;

            if (activeAttackPath.includes(id))
              return "#ef4444";

            if ((link.weight || 0) >= 5)
              return "#f97316";

            if ((link.weight || 0) >= 3)
              return "#facc15";

            return "#475569";
          }}
          onNodeClick={(node) => {

  console.log("Clicked node:", node);

  setSelectedNode(node);

  if (updateKillChain) {
    updateKillChain(node);
  }

  if (setSelectedIncident) {
    setSelectedIncident({
      id: node.id,
      category: node.category,
      risk_score: node.max_score ?? node.score ?? 0,
      severity:
        (node.max_score ?? node.score ?? 0) >= 90
          ? "Critical"
          : (node.max_score ?? node.score ?? 0) >= 70
          ? "High"
          : "Medium",
      status: "Live Threat",
      ai_recommendation:
        "Investigate the complete attack chain."
    });
  }

  const connectedLinks = safeLinks.filter((l) => {
    const source =
      typeof l.source === "object"
        ? l.source.id
        : l.source;

    const target =
      typeof l.target === "object"
        ? l.target.id
        : l.target;

    return source === node.id || target === node.id;
  });

  if (setHighlightLinks) {
    setHighlightLinks(new Set(connectedLinks));
  }

  const connectedNodes = new Set();

  connectedLinks.forEach((l) => {
    connectedNodes.add(
      typeof l.source === "object"
        ? l.source.id
        : l.source
    );

    connectedNodes.add(
      typeof l.target === "object"
        ? l.target.id
        : l.target
    );
  });

  connectedNodes.add(node.id);

  if (setHighlightNodes) {
    setHighlightNodes(connectedNodes);
  }

}}
          nodeCanvasObject={(node, ctx) => {
            const risk =
              node.max_score ?? node.score ?? 0;

            ctx.beginPath();
            ctx.arc(node.x, node.y, 12, 0, Math.PI * 2);

            ctx.fillStyle =
              risk >= 90
                ? "#ef4444"
                : risk >= 70
                ? "#f97316"
                : risk >= 40
                ? "#facc15"
                : "#22c55e";

            ctx.fill();

            ctx.strokeStyle = highlightNodes.has(node.id)
              ? "#00ffc8"
              : "#ffffff";

            ctx.lineWidth = highlightNodes.has(node.id)
              ? 5
              : 2;

            ctx.stroke();

            ctx.fillStyle = "#ffffff";
            ctx.font = "bold 10px Arial";
            ctx.textAlign = "center";

            ctx.fillText(
              node.category,
              node.x,
              node.y + 28
            );
          }}
        />
      </div>

      {selectedNode && (
        <div
          style={{
            marginTop: 20,
            background: "#0f172a",
            padding: 20,
            borderRadius: 12
          }}
        >
          <h3 style={{ color: "#00ffc8" }}>
            Threat Details
          </h3>

          <p>
            <b>Category:</b> {selectedNode.category}
          </p>

          <p>
            <b>Risk:</b>{" "}
            {selectedNode.max_score ??
              selectedNode.score}
          </p>

          <p>
            <b>ID:</b> {selectedNode.id}
          </p>
        </div>
      )}
    </>
  );
}
