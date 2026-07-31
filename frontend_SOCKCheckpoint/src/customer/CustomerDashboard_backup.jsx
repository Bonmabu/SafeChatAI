import { useEffect, useState, useRef } from "react";
import axios from "axios";
import CustomerNav from "./CustomerNav";
import ForceGraph2D from "react-force-graph-2d";
import AttackMap from "../components/AttackMap";

const API = "http://127.0.0.1:8000";

function Card({ title, value }) {
  return (
    <div
      style={{
        background: "rgba(17,24,39,0.75)",
        borderRadius: 16,
        padding: 20,
        border: "1px solid rgba(255,255,255,0.08)",
        boxShadow: "0 10px 30px rgba(0,0,0,0.35)"
      }}
    >
      <h3 style={{ color: "#d1d5db", margin: 0 }}>{title}</h3>
      <h1 style={{ color: "#00ffd5", marginBottom: 18,
fontSize: 28 }}>
        {value}
      </h1>
    </div>
  );
}
function startReplay() {
  if (!replayData || replayData.length === 0) return;

  setIsReplaying(true);
  setIsPaused(false);

  let i = 0;

  replayIntervalRef.current = setInterval(() => {
    if (isPaused) return;

    if (i >= replayData.length) {
      clearInterval(replayIntervalRef.current);
      setIsReplaying(false);
      return;
    }

    setReplayProgress((i / replayData.length) * 100);

    const current = replayData[i];
    setGraphData(current);

    const focusNode = current.nodes?.[current.nodes.length - 1];

    if (focusNode && graphRef.current) {
      setTimeout(() => {
        graphRef.current.centerAt(focusNode.x || 0, focusNode.y || 0, 800);
        graphRef.current.zoom(4, 800);
      }, 100);
    }

    i++;
  }, replaySpeed);
}
function togglePauseReplay() {
  setIsPaused((prev) => !prev);
}
function stopReplay() {
  clearInterval(replayIntervalRef.current);
  setIsReplaying(false);
  setIsPaused(false);

  const current = replayData[replayIndex];

setGraphData(current);

// pause-on-critical logic
const node = current.nodes?.[current.nodes.length - 1];

if (node?.score >= 85) {
  setIsPaused(true);
  }
}
export default function CustomerDashboard() {
  const tenantId = "demo";

  const graphRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState("");
  const [socket, setSocket] = useState(null);
  const [alerts, setAlerts] = useState([]);
const [replayIndex, setReplayIndex] = useState(0);
const [replayData, setReplayData] = useState([]);
const [aiSummary, setAiSummary] = useState("");
const [generating, setGenerating] = useState(false);
const [timelineIndex, setTimelineIndex] = useState(0);
const [isReplaying, setIsReplaying] = useState(false);
const [timelineData, setTimelineData] = useState([]);
const [replaySpeed, setReplaySpeed] = useState(800);
const [isPaused, setIsPaused] = useState(false);
const replayIntervalRef = useRef(null);
const [replayProgress, setReplayProgress] = useState(0);
const [highestRiskNode, setHighestRiskNode] = useState(null);
const [currentThreatLevel, setCurrentThreatLevel] = useState("LOW");
const [searchNode, setSearchNode] = useState("");
const [highlightNodes, setHighlightNodes] = useState(new Set());
const [highlightLinks, setHighlightLinks] = useState(new Set());
const [playbackIndex, setPlaybackIndex] = useState(-1);
const playbackTimer = useRef(null);
const [userInput, setUserInput] = useState("");
const [chatLog, setChatLog] = useState([]);
const [chatLoading, setChatLoading] = useState(false);
const [streamingText, setStreamingText] = useState("");


  const [summary, setSummary] = useState({
    total_scans: 0,
    total_alerts: 0,
    total_incidents: 0,
    security_score: 100
  });

  const [graphData, setGraphData] = useState({
  nodes: [],
  links: []
});
const [rootNode, setRootNode] = useState(null);
useEffect(() => {
  loadDashboard();
  loadGraph();
  startLiveStream();

  return () => {
    if (socket) socket.close();
  };
}, []);
useEffect(() => {
  if (alerts.length > 5) {
    setAlerts((prev) => prev.slice(0, 5));
  }
}, [alerts]);

  useEffect(() => {
  loadDashboard();
  loadGraph();
  startLiveStream();

  // 🔴 ADD THIS: auto refresh KPIs every 5 seconds
  const interval = setInterval(() => {
    loadDashboard();
  }, 5000);

  return () => {
    clearInterval(interval);
    if (socket) socket.close();
  };
}, []);

  async function loadDashboard() {
    try {
      const res = await axios.get(`${API}/customer/dashboard`, {
        params: { tenant_id: tenantId }
      });

      setSummary(res.data);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }
async function generateIncidentSummary() {
  try {
    setGenerating(true);

    const currentGraph =
  isReplaying && replayData[replayIndex]
    ? replayData[replayIndex]
    : graphData;

const payload = {
  nodes: currentGraph.nodes.map((n) => ({
        id: n.id,
        category: n.category,
        score: n.score,
        stage: n.stage,
        mitre: n.mitre
      })),

      links: currentGraph.links.map((l) => ({
        source:
          typeof l.source === "object"
            ? l.source.id
            : l.source,

        target:
          typeof l.target === "object"
            ? l.target.id
            : l.target
      })),

      alerts: alerts.map((a) => ({
        id: a.id,
        message: a.message,
        severity: a.severity
      }))
    };

    const res = await axios.post(`${API}/soc-ai`, payload);

    setAiSummary(res.data);
  } catch (err) {
    console.log(err.response?.data);
  } finally {
    setGenerating(false);
  }
}
function getMitreTechnique(node) {
  const type = (node.category || "").toLowerCase();
  const score = node.score || 0;

  if (type.includes("phishing")) return "T1566 - Phishing";
  if (type.includes("malware")) return "T1204 - User Execution";
  if (type.includes("ip")) return "T1595 - Active Scanning";
  if (type.includes("device")) return "T1190 - Exploit Public-Facing App";
  if (score >= 85) return "TA0008 - Lateral Movement";
  if (score >= 70) return "TA0011 - Command & Control";

  return "TA0001 - Initial Access";
}
async function loadGraph() {
  try {
    const res = await axios.get(`${API}/incidents`, {
  params: {
    tenant_id: tenantId
  }
});

    const incidents = res.data || [];
console.log("INCIDENTS:", incidents);

    const nodes = incidents.map((item) => ({
  id: `incident-${item.id}`,
  category: item.category || "Unknown",
  score: Number(item.risk_score ?? 50),
  stage: getAttackStage({
    category: item.category,
    score: Number(item.risk_score ?? 50)
  }),
  mitre: getMitreTechnique({
    category: item.category,
    score: Number(item.risk_score ?? 50)
  })
}));
if (nodes.length > 0 && !rootNode) {
  setRootNode(nodes[0]); // first infected = root cause
}

    const links = incidents.map((item, i) => ({
      source: `incident-${item.id}`,
      target: `incident-${incidents[i - 1]?.id || item.id}`
    }));
console.log("NODES:", nodes);
console.log("LINKS:", links);

    setGraphData({
      nodes,
      links
    });

  } catch (err) {
    console.error("Graph load failed:", err);
  }
}
function getAttackStage(node) {
  const type = (node.category || "").toLowerCase();
  const score = node.score || 0;

  if (type.includes("scan") || type.includes("ip")) {
    return "RECONNAISSANCE";
  }

  if (type.includes("phishing")) {
    return "INITIAL ACCESS";
  }

  if (type.includes("malware")) {
    return "EXECUTION";
  }

  if (score >= 70 && score < 85) {
    return "LATERAL MOVEMENT";
  }

  if (score >= 85) {
    return "IMPACT / EXFILTRATION";
  }

  return "UNKNOWN";
}
function startLiveStream() {
  const ws = new WebSocket("ws://127.0.0.1:8000/ws/incidents");

  ws.onopen = () => {
    console.log("LIVE STREAM CONNECTED");
  };

  ws.onmessage = (event) => {
  try {
    const incident = JSON.parse(event.data);

    const newNode = {
  id: `incident-${incident.id || Date.now()}`,
  category: incident.category || "Unknown",
  score: Number(incident.risk_score ?? 50),
stage: getAttackStage({
  category: incident.category,
  score: Number(incident.risk_score ?? 50)
}),


  // 🔴 ATTACK TRACE DATA
  parent: incident.source || null,
  targetSystem: incident.target || "unknown",
  timestamp: incident.time || new Date().toISOString()
};
setTimelineData((prev) => [...prev, newNode].slice(-100));
setReplayData((prev) => [
  ...prev,
  {
    nodes: [...graphData.nodes],
    links: [...graphData.links],
    timestamp: Date.now()
  }
]);
    setGraphData((prev) => {
      const nodes = [...prev.nodes, newNode];

      const links = [...prev.links];

// 🔴 REAL ATTACK FLOW
if (newNode.parent) {
  links.push({
    source: newNode.parent,
    target: newNode.id
  });
} else {
  links.push({
    source: nodes[nodes.length - 2]?.id || newNode.id,
    target: newNode.id
  });
}
const highest = nodes.reduce(
  (a, b) => (a.score > b.score ? a : b),
  nodes[0]
);

setHighestRiskNode(highest);

if (highest.score >= 90) {
  setCurrentThreatLevel("CRITICAL");
} else if (highest.score >= 75) {
  setCurrentThreatLevel("HIGH");
} else if (highest.score >= 50) {
  setCurrentThreatLevel("MEDIUM");
} else {
  setCurrentThreatLevel("LOW");
}

      return {
        nodes: nodes.slice(-60),
        links: links.slice(-60)
      };
    });

    // 🚨 CRITICAL ALERT TRIGGER
    if (newNode.score >= 85) {
      setAlerts((prev) => [
        {
          id: Date.now(),
          message: `CRITICAL THREAT: ${newNode.category}`,
          severity: newNode.score
        },
        ...prev.slice(0, 5)
      ]);

      console.log("🚨 CRITICAL ALERT:", newNode);
    }

  } catch (err) {
    console.error("WS error:", err);
  }
};
  ws.onerror = (err) => {
    console.error("WebSocket error:", err);
  };

  setSocket(ws);
}

  if (loading) {
    return (
      <div style={{ padding: 40, color: "white" }}>
        Loading Customer Dashboard...
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        padding: 25,
        color: "white",
        background:
          "radial-gradient(circle at top,#111827 0%,#0b1220 40%,#070b14 100%)"
      }}
    >
      <CustomerNav />

      {/* HEADER */}
      <h1
        style={{
          textAlign: "center",
          fontSize: 34,
          fontWeight: "bold",
          marginBottom: 30,
          color: "#ffffff",
          textShadow: "0 0 15px rgba(0,255,255,0.5)"
        }}
      >
        🛡 Customer Security Dashboard
      </h1>
{alerts.length > 0 && (
  <div
    style={{
      marginBottom: 20,
      background: "#1f2937",
      border: "1px solid #ef4444",
      padding: 12,
      borderRadius: 10,
      maxHeight: 160,
      overflowY: "auto"
    }}
  >
    <h3 style={{ color: "#ef4444", marginBottom: 10 }}>
      🚨 LIVE ALERTS
    </h3>

    {alerts.map((a) => (
      <div key={a.id} style={{ color: "#fff", marginBottom: 6 }}>
        {a.message} (Risk: {a.severity})
      </div>
    ))}
  </div>
)}

      {/* CARDS */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 18,
          marginBottom: 30
        }}
      >
        <Card title="Total Scans" value={summary?.total_scans ?? 0} />
        <Card title="Alerts" value={summary?.total_alerts ?? 0} />
        <Card title="Incidents" value={summary?.total_incidents ?? 0} />
        <Card
  title="Security Score"
  value={
    <span style={{
      color:
        summary?.security_score >= 80
          ? "#00ff88"
          : summary?.security_score >= 50
          ? "#ffcc00"
          : "#ff3b30"
    }}>
      {summary?.security_score ?? 0}%
    </span>
  }
/>
        
      </div>

      {/* STATUS */}
{rootNode && (
  <div style={{
    marginTop: 10,
    padding: 10,
    borderRadius: 8,
    background: "#0f172a",
    border: "1px solid #22c55e",
    color: "#22c55e"
  }}>
    🧠 Root Cause Detected: <b>{rootNode.id}</b>
  </div>
)}
      <div
        style={{
          background: "rgba(17,24,39,0.75)",
          borderRadius: 16,
          padding: 20,
          marginBottom: 25,
          border: "1px solid rgba(255,255,255,0.08)"
        }}
      >
        <h2 style={{ color: "#fff" }}>🛡 Security Status</h2>
<div
  style={{
    marginBottom: 20,
    padding: 15,
    borderRadius: 12,
    background: "#111827",
    border: "1px solid #334155"
  }}
>
  <h3 style={{ color: "#00ffc8" }}>
    🧠 Live Threat Intelligence
  </h3>

  <p>
    <b>Threat Level:</b>{" "}
    <span
      style={{
        color:
          currentThreatLevel === "CRITICAL"
            ? "#ef4444"
            : currentThreatLevel === "HIGH"
            ? "#f97316"
            : currentThreatLevel === "MEDIUM"
            ? "#facc15"
            : "#22c55e"
      }}
    >
      {currentThreatLevel}
    </span>
  </p>

  <p>
    <b>Highest Risk:</b>{" "}
    {highestRiskNode?.score ?? "-"}
  </p>

  <p>
    <b>MITRE:</b>{" "}
    {highestRiskNode?.mitre ?? "-"}
  </p>

  <p>
    <b>Attack Stage:</b>{" "}
    {highestRiskNode?.stage ?? "-"}
  </p>

  <p>
    <b>Root Cause:</b>{" "}
    {rootNode?.id ?? "-"}
  </p>

  <p>
    <b>Last Incident:</b>{" "}
    {lastUpdated}
  </p>
</div>
        <p>Security Score: <b>{summary.security_score}%</b></p>
        <p style={{ color: "#9ca3af" }}>
          Last Updated: {lastUpdated}
        </p>
      </div>
{isReplaying && (
  <div style={{ marginBottom: 10 }}>
    <div style={{ height: 6, background: "#1f2937", borderRadius: 10 }}>
      <div
        style={{
          height: 6,
          width: `${replayProgress}%`,
          background: "#00ffc8",
          borderRadius: 10,
          transition: "width 0.2s"
        }}
      />
    </div>
    <p style={{ color: "#9ca3af", fontSize: 12 }}>
      Replay Progress: {Math.round(replayProgress)}%
    </p>
  </div>
)}
<div style={{ marginBottom: 10 }}>
  <button
    onClick={startReplay}
    disabled={isReplaying || timelineData.length === 0}
    style={{
      padding: "8px 14px",
      background: "#00ffc8",
      border: "none",
      borderRadius: 8,
      cursor: "pointer",
      fontWeight: "bold"
    }}
  >
    ▶ Replay Attack Timeline
  </button>
</div>
<div style={{ marginBottom: 20 }}>
  <textarea
    placeholder="Paste message / incident log / alert..."
    style={{
      width: "100%",
      height: 80,
      borderRadius: 10,
      padding: 10,
      background: "#0f172a",
      color: "#fff",
      border: "1px solid #334155"
    }}
    value={userInput}
    onChange={(e) => setUserInput(e.target.value)}
  />

  <button
    onClick={async () => {
      const res = await axios.post(`${API}/soc-ai`, {
        message: userInput
      });

      setAiSummary(res.data.data); // IMPORTANT: your JSON structure
    }}
    style={{
      marginTop: 10,
      padding: "10px 16px",
      background: "#00ffc8",
      border: "none",
      borderRadius: 8,
      fontWeight: "bold",
      cursor: "pointer"
    }}
  >
    🧠 Analyze Message
  </button>
</div>
<div style={{
  marginBottom: 20,
  padding: 15,
  borderRadius: 12,
  background: "#0b1220",
  border: "1px solid #334155"
}}>

  <h3 style={{ color: "#00ffc8", marginBottom: 10 }}>
    🧠 SOC AI Chat Analyzer
  </h3>

  {/* CHAT LOG */}
  <div style={{
    maxHeight: 200,
    overflowY: "auto",
    marginBottom: 10,
    padding: 10,
    background: "#111827",
    borderRadius: 8
  }}>
    {chatLog.map((msg, i) => (
      <div key={i} style={{ marginBottom: 8 }}>
        <b style={{ color: msg.role === "user" ? "#60a5fa" : "#22c55e" }}>
          {msg.role === "user" ? "User" : "SOC AI"}:
        </b>{" "}
        <span style={{ color: "#d1d5db" }}>
          {msg.text}
        </span>
      </div>
    ))}
  </div>

  {/* INPUT */}
  <textarea
    value={userInput}
    onChange={(e) => setUserInput(e.target.value)}
    placeholder="Paste incident, email, log, or alert..."
    style={{
      width: "100%",
      height: 80,
      borderRadius: 8,
      padding: 10,
      background: "#0f172a",
      color: "#fff",
      border: "1px solid #334155"
    }}
  />
<textarea
  value={userInput}
  onChange={(e) => setUserInput(e.target.value)}
  placeholder="Paste incident, email, log, or alert..."
  style={{
    width: "100%",
    height: 80,
    borderRadius: 8,
    padding: 10,
    background: "#0f172a",
    color: "#fff",
    border: "1px solid #334155"
  }}
/>

{/* 🔥 ADD STREAM OUTPUT RIGHT HERE */}
<div style={{
  marginTop: 10,
  padding: 10,
  background: "#0f172a",
  borderRadius: 8,
  color: "#22c55e",
  minHeight: 40
}}>
  {streamingText}
</div>

  <button
    disabled={chatLoading}
    onClick={async () => {
      if (!userInput.trim()) return;

      const newUserMsg = { role: "user", text: userInput };

      setChatLog((prev) => [...prev, newUserMsg]);
      setChatLoading(true);

      try {
        setStreamingText("");

const res = await fetch(`${API}/soc-ai-stream`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ message: userInput })
});

const reader = res.body.getReader();
const decoder = new TextDecoder();

let fullText = "";

while (true) {
  const { value, done } = await reader.read();
  if (done) break;

  const chunk = decoder.decode(value);
  fullText += chunk;

  setStreamingText(fullText); // LIVE UPDATE
}

        const ai = res.data.data;

        const aiMsg = {
          role: "ai",
          text:
            `Risk: ${ai.score} | ${ai.category} | ` +
            `MITRE: ${ai.mitre || "N/A"} | Status: ${ai.status}`
        };

        setChatLog((prev) => [...prev, aiMsg]);

        // OPTIONAL: auto inject into graph if malicious
        if (ai.score >= 70) {
          setAlerts((prev) => [
            {
              id: Date.now(),
              message: `AI DETECTED THREAT: ${ai.category}`,
              severity: ai.score
            },
            ...prev.slice(0, 5)
          ]);
        }

      } catch (err) {
        setChatLog((prev) => [
          ...prev,
          { role: "ai", text: "Error analyzing message" }
        ]);
      }

      setUserInput("");
      setChatLoading(false);
    }}
    style={{
      marginTop: 10,
      padding: "10px 16px",
      background: chatLoading ? "#334155" : "#00ffc8",
      border: "none",
      borderRadius: 8,
      fontWeight: "bold",
      cursor: "pointer"
    }}
  >
    {chatLoading ? "Analyzing..." : "🧠 Analyze"}
  </button>

</div>

      {/* GRAPH SECTION */}
      <div
        style={{
          background: "rgba(17,24,39,0.75)",
          borderRadius: 16,
          padding: 20,
          border: "1px solid rgba(255,255,255,0.08)"
        }}
      >
<div style={{ marginBottom: 10, color: "#9ca3af" }}>
  🧬 Kill Chain Tracking Enabled
</div>
        <h2 style={{ color: "#fff", marginBottom: 10 }}>
          🌐 Live Attack Graph
        </h2>
<div
  style={{
    display: "flex",
    gap: 10,
    marginBottom: 15
  }}
>
  <input
    type="text"
    placeholder="Search Node ID..."
    value={searchNode}
    onChange={(e) => setSearchNode(e.target.value)}
    style={{
      flex: 1,
      padding: 10,
      borderRadius: 8,
      border: "1px solid #334155",
      background: "#0f172a",
      color: "#fff"
    }}
  />

  <button
    onClick={() => {
      const node = graphData.nodes.find((n) =>
        n.id.toLowerCase().includes(searchNode.toLowerCase())
      );

      if (!node) return;

      setSelectedNode({
        ...node,
        attackPath: graphData.links.filter(
          (l) => l.source === node.id || l.target === node.id
        )
      });

      graphRef.current?.centerAt(node.x, node.y, 800);
      graphRef.current?.zoom(5, 800);
    }}
    style={{
      padding: "10px 16px",
      background: "#00ffc8",
      border: "none",
      borderRadius: 8,
      cursor: "pointer",
      fontWeight: "bold"
    }}
  >
    🔍 Locate
  </button>
</div>
<div style={{ display: "flex", gap: 10, marginBottom: 10 }}>
  <button
    onClick={() => {
      if (playbackTimer.current)
        clearInterval(playbackTimer.current);

      setPlaybackIndex(0);

      playbackTimer.current = setInterval(() => {
        setPlaybackIndex((prev) => {
          if (prev >= (graphData.nodes?.length || 0) - 1) {
            clearInterval(playbackTimer.current);
            return prev;
          }
          return prev + 1;
        });
      }, 1000);
    }}
  >
    ▶ Play
  </button>
</div>

  <div style={{ display: "flex", gap: 10, marginBottom: 15 }}>

  <button
    onClick={async () => {
      await generateIncidentSummary();
    }}
    disabled={generating}
    style={{
      padding: "10px 16px",
      background: "#2563eb",
      color: "#fff",
      border: "none",
      borderRadius: 8,
      cursor: generating ? "not-allowed" : "pointer"
    }}
  >
    {generating ? "Analyzing..." : "🧠 Generate Incident Summary"}
  </button>

</div>

  <button
    onClick={() => {
      setIsReplaying(true);
setReplayIndex(0);
setReplayProgress(0);

      if (playbackTimer.current)
        clearInterval(playbackTimer.current);

      setPlaybackIndex(0);

      playbackTimer.current = setInterval(() => {
        setPlaybackIndex(prev => {
          if (prev >= replayData[replayIndex]?.nodes.length - 1) {
            clearInterval(playbackTimer.current);
            setIsReplaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 1000);
    }}
    style={{
      padding: "10px 16px",
      background: "#22c55e",
      color: "#fff",
      border: "none",
      borderRadius: 8,
      cursor: "pointer"
    }}
  >
    ▶ Start Replay
  </button>

  <button
    onClick={() => clearInterval(playbackTimer.current)}
    style={{
      padding: "10px 16px",
      background: "#f59e0b",
      color: "#fff",
      border: "none",
      borderRadius: 8,
      cursor: "pointer"
    }}
  >
    ⏸ Pause
  </button>

  <button
    onClick={() => {
      clearInterval(playbackTimer.current);
      setPlaybackIndex(-1);
      setIsReplaying(false);
    }}
    style={{
      padding: "10px 16px",
      background: "#ef4444",
      color: "#fff",
      border: "none",
      borderRadius: 8,
      cursor: "pointer"
    }}
  >
    ⏹ Stop
  </button>

</div>

{aiSummary && (
  <div
    style={{
      marginBottom: 15,
      padding: 12,
      borderRadius: 10,
      background: "#111827",
      border: "1px solid #334155",
      color: "#9ca3af"
    }}
  >
    <h4 style={{ color: "#00ffc8" }}>🧠 AI Incident Summary</h4>

    <p><b>Summary:</b> {aiSummary.summary}</p>

    <p><b>Highest Risk Node:</b> {aiSummary.highest_risk?.id}</p>

    <p><b>Category:</b> {aiSummary.highest_risk?.category}</p>

    <p><b>Risk Score:</b> {aiSummary.highest_risk?.score}</p>

    <p><b>MITRE:</b> {aiSummary.highest_risk?.mitre}</p>

    <p><b>Attack Stage:</b> {aiSummary.highest_risk?.stage}</p>

    <hr style={{ margin: "15px 0", borderColor: "#334155" }} />

    <h4 style={{ color: "#22c55e" }}>🌱 Root Cause Analysis</h4>

    <p><b>Patient Zero:</b> {aiSummary.root_cause?.id}</p>

    <p><b>Category:</b> {aiSummary.root_cause?.category}</p>

    <p><b>Attack Stage:</b> {aiSummary.root_cause?.stage}</p>

    <p><b>MITRE:</b> {aiSummary.root_cause?.mitre}</p>

    <hr style={{ margin: "15px 0", borderColor: "#334155" }} />

    <h4 style={{ color: "#22c55e" }}>Recommendation</h4>

    <div
      style={{
        background: "#0f172a",
        padding: 10,
        borderRadius: 8,
        color: "#22c55e"
      }}
    >
      {aiSummary.recommendation}
    </div>
  </div>
)}
        {/* STATS BAR */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            marginBottom: 15,
            color: "#9ca3af"
          }}
        >
          <span>Nodes: {graphData?.nodes?.length ?? 0}</span>
          <span>Connections: {graphData?.links?.length ?? 0}</span>
          <span>Status: LIVE</span>
        </div>

        {/* GRAPH */}
        <div style={{ height: 420, borderRadius: 12, overflow: "hidden" }}>
          <ForceGraph2D
  ref={graphRef}
  graphData={graphData}
  backgroundColor="#050b14"

  nodeRelSize={6}
  cooldownTicks={120}
  warmupTicks={60}
  cooldownTime={2500}
  d3AlphaDecay={0.015}
  d3VelocityDecay={0.25}

  linkWidth={(link) =>
    highlightLinks.has(link) ? 3 : 1.2
  }

  linkColor={(link) =>
    highlightLinks.has(link) ? "#00ffff" : "rgba(148,163,184,0.25)"
  }

  linkDirectionalArrowLength={6}
  linkDirectionalArrowRelPos={1}
  linkCurvature={0.25}

  nodeLabel={(node) =>
    `${node.id} | ${node.category} | Risk: ${node.score} | ${node.mitre}`
  }

  nodeColor={(node) => {
    if (node.score >= 85) return "#ff3b30";
    if (node.score >= 70) return "#ff9500";
    if (node.score >= 50) return "#facc15";
    return "#00ffc8";
  }}

  nodeVal={(node) => {
    const base = Math.max(3, (node.score || 10) / 5);
    return base + (node.score >= 85 ? 5 : node.score >= 60 ? 2 : 0);
  }}

  // 🔥 NEW: professional glow + labels
  nodeCanvasObject={(node, ctx, globalScale) => {
    const size = Math.max(4, (node.score || 10) / 4);

    // glow ring
    ctx.beginPath();
    ctx.arc(node.x, node.y, size + 5, 0, 2 * Math.PI);
    ctx.fillStyle =
      node.score >= 85
        ? "rgba(255, 59, 48, 0.15)"
        : node.score >= 70
        ? "rgba(255, 149, 0, 0.12)"
        : "rgba(0, 255, 200, 0.06)";
    ctx.fill();

    // node core
    ctx.beginPath();
    ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
    ctx.fillStyle =
      node.score >= 85
        ? "#ff3b30"
        : node.score >= 70
        ? "#ff9500"
        : "#00ffc8";
    ctx.fill();

    // label (only when zoomed in)
    if (globalScale > 1.2) {
      ctx.fillStyle = "#ffffff";
      ctx.font = `${12 / globalScale}px Sans-Serif`;
      ctx.fillText(node.id, node.x + size + 2, node.y + size + 2);
    }
  }}

  onNodeClick={(node) => {
    const nodes = new Set();
    const links = new Set();

    nodes.add(node);

    graphData.links.forEach((link) => {
      const source =
        typeof link.source === "object" ? link.source.id : link.source;

      const target =
        typeof link.target === "object" ? link.target.id : link.target;

      if (source === node.id || target === node.id) {
        links.add(link);

        graphData.nodes.forEach((n) => {
          if (n.id === source || n.id === target) {
            nodes.add(n);
          }
        });
      }
    });

    setHighlightNodes(nodes);
    setHighlightLinks(links);

    setSelectedNode({
      ...node,
      attackPath: graphData.links.filter((l) => {
        const source =
          typeof l.source === "object" ? l.source.id : l.source;
        const target =
          typeof l.target === "object" ? l.target.id : l.target;

        return source === node.id || target === node.id;
      })
    });

    graphRef.current?.centerAt(node.x, node.y, 800);
    graphRef.current?.zoom(4, 800);
  }}
/>
      
{/* SELECTED NODE */}
{selectedNode && (
          <div
            style={{
              marginTop: 20,
              padding: 15,
              borderRadius: 12,
              background: "#111827",
              border: "1px solid #334155"
            }}
          >
            <h3 style={{ color: "#00ffc8" }}>Selected Asset</h3>

            <p><b>ID:</b> {selectedNode.id}</p>
            <p><b>Type:</b> {selectedNode.category}</p>
            <p><b>Risk:</b> {selectedNode.score}</p>
            <p><b>Attack Stage:</b> {selectedNode.stage}</p>
            <p><b>MITRE Technique:</b> {selectedNode.mitre}</p>

            {selectedNode.attackPath?.length > 0 && (
              <div style={{ marginTop: 10, color: "#9ca3af" }}>
                <h4>Attack Chain</h4>

                {selectedNode.attackPath.map((a, i) => (
  <div key={i}>
    {typeof a.source === "object" ? a.source.id : a.source}
    {" → "}
    {typeof a.target === "object" ? a.target.id : a.target}
  </div>
))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* GLOBAL ATTACK MAP */}
      <div
        style={{
          marginTop: 25,
          background: "rgba(17,24,39,0.75)",
          padding: 20,
          borderRadius: 16,
          border: "1px solid rgba(255,255,255,0.08)"
        }}
      >
        <h2 style={{ color: "#fff", marginBottom: 15 }}>
          🌍 Global Attack Map
        </h2>

        <AttackMap nodes={graphData.nodes} />
      </div>

    </div>
  );
}