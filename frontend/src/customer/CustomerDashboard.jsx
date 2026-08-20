import { useEffect, useState, useRef } from "react";
import axios from "axios";
const getTenantId = () => {
  const token = localStorage.getItem("token");

  if (!token) return null;

  try {
    return JSON.parse(atob(token.split(".")[1])).tenant_id;
  } catch {
    return null;
  }
};
const getAuthConfig = () => ({
  headers: {
    Authorization: `Bearer ${localStorage.getItem("token")}`
  }
});
import CustomerNav from "./CustomerNav";
import ForceGraph2D from "react-force-graph-2d";
import AttackMap from "../components/AttackMap";
import SOCAssistant from "./SOCAssistant";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from "recharts";
const API = import.meta.env.VITE_API_BASE;
const token = localStorage.getItem("token");
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
export default function CustomerDashboard() {
  const tenantId = getTenantId();
  const graphRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState("");
  const [socket, setSocket] = useState(null);
  const [alerts, setAlerts] = useState([]);
const [campaign, setCampaign] = useState(null);
const [iocs, setIocs] = useState([]);
const [threatDNA, setThreatDNA] = useState([]);
const [responseTimeline, setResponseTimeline] = useState([]);
const [replayIndex, setReplayIndex] = useState(0);
const [replayData, setReplayData] = useState([]);
const [aiSummary, setAiSummary] = useState("");
const [generating, setGenerating] = useState(false);
const [timelineIndex, setTimelineIndex] = useState(0);
const [isReplaying, setIsReplaying] = useState(false);
const [timelineData, setTimelineData] = useState([]);
const [attackTrend, setAttackTrend] = useState([]);
const [replaySpeed, setReplaySpeed] = useState(800);
const [isPaused, setIsPaused] = useState(false);
const replayIntervalRef = useRef(null);
const [replayProgress, setReplayProgress] = useState(0);
const [highestRiskNode, setHighestRiskNode] = useState(null);
const [currentThreatLevel, setCurrentThreatLevel] = useState("LOW");
const [threatStats, setThreatStats] = useState({
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0
});
const [playbackIndex, setPlaybackIndex] = useState(-1);
const playbackTimer = useRef(null);
const [searchNode, setSearchNode] = useState("");
const [highlightNodes, setHighlightNodes] = useState(new Set());
const [highlightLinks, setHighlightLinks] = useState(new Set());
const [userInput, setUserInput] = useState("");
const [chatLog, setChatLog] = useState([]);
const [chatLoading, setChatLoading] = useState(false);
const [streamingText, setStreamingText] = useState("");
function startReplay() {
  if (!replayData || replayData.length === 0) return;

  clearInterval(replayIntervalRef.current);

  setReplayIndex(0);
  setReplayProgress(0);
  setIsReplaying(true);
  setIsPaused(false);

  let i = 0;

  replayIntervalRef.current = setInterval(() => {
    setIsPaused((paused) => {
      if (paused) return paused;

      if (i >= replayData.length) {
        clearInterval(replayIntervalRef.current);
        setIsReplaying(false);
        return paused;
      }

      const current = replayData[i];

      if (current) {
        setReplayIndex(i);

        /*
         * Backend replay events are individual security events.
         * If the event already contains graph data, display it.
         * Otherwise keep the current graph and update the replay state.
         */
        if (current.nodes && current.links) {
          setGraphData({
            nodes: current.nodes,
            links: current.links
          });
        }

        setReplayProgress(
          ((i + 1) / replayData.length) * 100
        );
      }

      i++;

      return paused;
    });
  }, replaySpeed);
}
function togglePauseReplay() {
  setIsPaused((prev) => !prev);
}
function stopReplay() {
  clearInterval(replayIntervalRef.current);
  replayIntervalRef.current = null;

  setIsReplaying(false);
  setIsPaused(false);
  setReplayIndex(0);
  setReplayProgress(0);

  if (replayData.length > 0) {
    setGraphData(replayData[0]);
  }
}
  const [summary, setSummary] = useState({});
const [socSummary, setSocSummary] = useState({});

  const [graphData, setGraphData] = useState({
  nodes: [],
  links: []
});
const [rootNode, setRootNode] = useState(null);

useEffect(() => {
  if (alerts.length > 5) {
    setAlerts((prev) => prev.slice(0, 5));
  }
}, [alerts]);

  useEffect(() => {
  loadDashboard();
  loadGraph();
  loadAttackTrend();
  loadIOCs();
  loadThreatDNA();
  loadReplay();

  const ws = startLiveStream();

  const interval = setInterval(() => {
    loadDashboard();
    loadSummary();
    loadIOCs();
    loadThreatDNA();
    loadReplay();
  }, 5000);

  return () => {
    clearInterval(interval);

    if (ws) {
      ws.close();
    }
  };
}, []);
async function loadSummary() {
  try {
    const res = await axios.get(
      `${API}/soc-summary`,
      getAuthConfig()
    );
setSocSummary(res.data);
  } catch (err) {
    console.error("SOC SUMMARY ERROR:", err);
  }
}

  async function loadDashboard() {
    try {
      const res = await axios.get(
  `${API}/customer/dashboard`,
  getAuthConfig()
);

      console.log("Dashboard API Response:", res.data);
setSummary(res.data);
const incidents = await axios.get(
  `${API}/incidents`,
  getAuthConfig()
);

const stats = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0
};

incidents.data.forEach(i => {

    if (i.risk_score >= 90)
        stats.Critical++;

    else if (i.risk_score >= 75)
        stats.High++;

    else if (i.risk_score >= 50)
        stats.Medium++;

    else
        stats.Low++;

});

setThreatStats(stats);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }
async function loadAttackTrend() {

  console.log("ATTACK TREND FUNCTION CALLED");

  try {

    console.log(
      "CALLING URL =",
      `${API}/customer/attack-trend`
    );

   const res = await axios.get(`${API}/customer/attack-trend`, {
  headers: getAuthConfig().headers
});

    console.log("TREND DATA =", res.data);

    setAttackTrend(res.data);

  } catch(err){

    console.error(
      "ATTACK TREND ERROR =",
      err.response?.data || err.message
    );

  }
}
async function loadIOCs() {
  try {

    const token = localStorage.getItem("token");

    const res = await axios.get(`${API}/customer/iocs`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    setIocs(res.data);

  } catch (err) {
    console.error("IOC LOAD ERROR:", err);
  }
}
async function loadThreatDNA() {
  try {
    const res = await axios.get(
  `${API}/threat-dna`,
  getAuthConfig()
);

    setThreatDNA(res.data?.fingerprints || []);

  } catch (err) {
    console.error("THREAT DNA LOAD ERROR:", err);
  }
}
async function loadReplay() {
  try {
    const res = await axios.get(
  `${API}/attack-replay`,
  getAuthConfig()
);

    const replay = Array.isArray(res.data)
  ? res.data
  : res.data?.events || [];

// Convert backend replay events into graph snapshots
const replaySnapshots = replay.map((event, index) => {
  const nodeId =
    event.username ||
    event.hostname ||
    event.source_ip ||
    `replay-${index}`;

  const node = {
    id: nodeId,
    category: event.category || "Unknown",
    score: Number(event.score || 0),
    stage: event.stage || "Unknown",
    mitre: event.mitre || "Unknown",
    source_ip: event.source_ip || "",
    hostname: event.hostname || "",
    username: event.username || "",
    time: event.time || ""
  };

  return {
    time: event.time || "",
    nodes: [node],
    links: []
  };
});

setReplayData(replaySnapshots);

if (replaySnapshots.length === 0) {
  setReplayIndex(0);
  setReplayProgress(0);
}
  } catch (err) {
    console.error("THREAT REPLAY LOAD ERROR:", err);
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

    const res = await axios.post(
  `${API}/soc-ai`,
  payload,
  getAuthConfig()
);
console.log(res.data);

console.log("SOC AI RESPONSE =", res.data);

setAiSummary(res.data);
setCampaign(res.data.primary_campaign);
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
    const res = await axios.get(
  `${API}/incidents`,
 getAuthConfig()
);

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

    if (nodes.length) {
    const highest = [...nodes].sort((a, b) => b.score - a.score)[0];

    setHighestRiskNode(highest);

    if (highest.score >= 90)
        setCurrentThreatLevel("CRITICAL");
    else if (highest.score >= 75)
        setCurrentThreatLevel("HIGH");
    else if (highest.score >= 50)
        setCurrentThreatLevel("MEDIUM");
    else
        setCurrentThreatLevel("LOW");
}

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
const WS_URL =
  import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8000/ws/soc";
  const ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    console.log("LIVE STREAM CONNECTED");
  };

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);

    if (!msg.type && msg.event_type) {
        msg.type = msg.event_type;
    }

    console.log(msg);

    switch (msg.type) {

        case "ioc_update":
            setIocs(prev => {
                const existing = prev.find(x => x.id === msg.data.id);

                if (existing) {
                    return prev.map(x =>
                        x.id === msg.data.id ? msg.data : x
                    );
                }

                return [msg.data, ...prev].slice(0, 50);
            });
            break;

        case "alert":
            setAlerts(prev => [msg, ...prev].slice(0, 20));
            break;

        case "attack_graph":

{
    const nodes = msg.nodes || [];
    const links = (msg.links || []).filter(link => {

    if (!link) return false;

        const source =
            typeof link.source === "object"
            ? link.source.id
            : link.source;

        const target =
            typeof link.target === "object"
            ? link.target.id
            : link.target;

        return (
            nodes.some(n => n.id === source) &&
            nodes.some(n => n.id === target)
        );

    });


    setGraphData({
        nodes,
        links
    });
}

break;
        case "executive_dashboard":

    console.log("Executive dashboard event received");

    // This event is broadcast globally by the SOC engine.
    // Customer Dashboard does not need to process it.
    break;
        case "threat_intelligence":

    console.log("Threat intelligence event received");

    // Global SOC intelligence event.
    // Customer Dashboard does not need to process it directly.
    break;

        
        case "dashboard_update":

    loadDashboard();

    setThreatStats(prev => {
        const stats = { ...prev };

        if (msg.data.score >= 90)
            stats.Critical++;

        else if (msg.data.score >= 75)
            stats.High++;

        else if (msg.data.score >= 50)
            stats.Medium++;

        else
            stats.Low++;

        return stats;
    });

    break;

                case "response_timeline":
        case "auto_response_event":

            setResponseTimeline(prev => [
                {
                    time: msg.timestamp || new Date().toLocaleTimeString(),
                    level: msg.data?.level || "UNKNOWN",
                    actions: msg.data?.actions || [],
                    escalation: msg.data?.escalation || false
                },
                ...prev
            ].slice(0,20));

            break;


        case "ai_decision_event":

            console.log("AI decision event received", msg);

            setResponseTimeline(prev => [
                {
                    time: msg.timestamp || new Date().toLocaleTimeString(),
                    level: msg.data?.decision?.recommended_action?.level || "AI",
                    actions:
                        msg.data?.decision?.recommended_action?.actions || [],
                    escalation:
                        msg.data?.decision?.recommended_action?.escalation || false,
                    source: "SOC AI"
                },
                ...prev
            ].slice(0,20));

            break;

        case "new_threat":

            setTimelineData(prev => [...prev,msg.node]);
            break;

        case "alert_event":

            setAttackTrend(prev=>[
                ...prev.slice(-49),
                {
                    time:new Date().toLocaleTimeString(),
                    score:msg.score
                }
            ]);

            break;

        case "attack_graph_live":

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

        default:
            console.log("Unknown websocket event",msg);
    }
};
 ws.onerror = (err) => {
  console.error("WebSocket error:", err);
};
  setSocket(ws);

  return ws;
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
      {socSummary?.security_score ?? 0}%
    </span>
  }
/>
        
      </div>
<div
  style={{
    background: "rgba(17,24,39,0.75)",
    borderRadius: 16,
    padding: 20,
    marginBottom: 25
  }}
>
  <h2 style={{ color: "#fff" }}>
    📈 Live Attack Trend
  </h2>

  <div
  style={{
    width: "100%",
    height: 350,
    minHeight: 350,
    display: "block"
  }}
>
<div style={{color:"#00ffc8"}}>
  Points: {attackTrend.length}
</div>
  <ResponsiveContainer width="100%" height={350}>
    <LineChart data={attackTrend}>
      <CartesianGrid stroke="#334155" />
      <XAxis dataKey="time" />
      <YAxis />
      <Tooltip />
      <Line
        type="monotone"
        dataKey="score"
        stroke="#00ffc8"
        strokeWidth={3}
        dot={false}
      />
    </LineChart>
  </ResponsiveContainer>
</div>

</div>

      {/* STATUS */}
{rootNode && (
  <div
    style={{
      marginTop: 10,
      marginBottom: 15,
      padding: 10,
      borderRadius: 8,
      background: "#0f172a",
      border: "1px solid #22c55e",
      color: "#22c55e"
    }}
  >
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
<div
  style={{
    display: "flex",
    justifyContent: "center",
    marginBottom: 25
  }}
>
  <div
    style={{
  width: 180,
  height: 180,
  borderRadius: "50%",
  border: `12px solid ${
    currentThreatLevel === "CRITICAL"
      ? "#ef4444"
      : currentThreatLevel === "HIGH"
      ? "#f97316"
      : currentThreatLevel === "MEDIUM"
      ? "#facc15"
      : "#22c55e"
  }`,
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
  background: "#0f172a",
  boxShadow: "0 0 30px rgba(0,255,255,.25)"
}}
  >
    <div style={{ fontSize: 18, color: "#94a3b8" }}>
      Cyber Risk
    </div>

    <div
      style={{
        fontSize: 46,
        fontWeight: "bold",
        color: "#fff"
      }}
    >
      {highestRiskNode?.score || 0}
    </div>

    <div
      style={{
        color:
          currentThreatLevel === "CRITICAL"
            ? "#ef4444"
            : currentThreatLevel === "HIGH"
            ? "#f97316"
            : currentThreatLevel === "MEDIUM"
            ? "#facc15"
            : "#22c55e",
        fontWeight: "bold"
      }}
    >
      {currentThreatLevel}
    </div>
  </div>
</div>
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
{aiSummary?.soc_brain?.reasoning && (
  <>
    <hr style={{ margin: "15px 0", borderColor: "#334155" }} />

    <h3 style={{ color: "#38bdf8" }}>
      🧠 Autonomous SOC Brain
    </h3>

    <p>
      <b>Predicted Next Stage:</b>{" "}
      {aiSummary.soc_brain.predicted_next_stage}
    </p>

    <p>
      <b>Confidence:</b>{" "}
      {aiSummary.soc_brain.confidence}%
    </p>

    <p>
      <b>Decision Level:</b>{" "}
      {aiSummary.soc_brain.recommended_action.level}
    </p>

    <p>
      <b>Escalation:</b>{" "}
      {aiSummary.soc_brain.recommended_action.escalation
        ? "YES"
        : "NO"}
    </p>

    <h4 style={{ color: "#22c55e" }}>
      Recommended Actions
    </h4>

    {aiSummary.soc_brain.recommended_action.actions.map(
      (action, i) => (
        <div key={i}>✅ {action}</div>
      )
    )}
  </>
)}
<hr style={{ margin: "15px 0", borderColor: "#334155" }} />

<h3 style={{ color: "#00ffc8" }}>
  🔥 Threat Heat Map
</h3>

<div
  style={{
    display: "grid",
    gridTemplateColumns: "repeat(4,1fr)",
    gap: 10,
    marginTop: 10
  }}
>
  <div
    style={{
      background: "#7f1d1d",
      padding: 10,
      borderRadius: 8,
      textAlign: "center"
    }}
  >
    <h2>{threatStats.Critical}</h2>
    <small>Critical</small>
  </div>

  <div
    style={{
      background: "#9a3412",
      padding: 10,
      borderRadius: 8,
      textAlign: "center"
    }}
  >
    <h2>{threatStats.High}</h2>
    <small>High</small>
  </div>

  <div
    style={{
      background: "#854d0e",
      padding: 10,
      borderRadius: 8,
      textAlign: "center"
    }}
  >
    <h2>{threatStats.Medium}</h2>
    <small>Medium</small>
  </div>

  <div
    style={{
      background: "#166534",
      padding: 10,
      borderRadius: 8,
      textAlign: "center"
    }}
  >
    <h2>{threatStats.Low}</h2>
    <small>Low</small>
  </div>
</div>

<p>
  <b>Security Score:</b> {summary.security_score}%
</p>

<p style={{ color: "#9ca3af" }}>
  Last Updated: {lastUpdated}
</p>

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
    disabled={isReplaying || replayData.length === 0}
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

    if (chatLoading) return;

    if (!userInput.trim()) return;

    setChatLoading(true);

    try {

        setStreamingText("");

        setChatLog(prev => [
            ...prev,
            {
                role: "user",
                text: userInput
            }
        ]);

        const token = localStorage.getItem("token");

        const res = await fetch(`${API}/soc-ai-stream`, {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify({
        text: userInput
    })
});

        const response = await res.json();

        if (!response.success)
            throw new Error("Analysis failed");

        const ai = response.data;

        setAiSummary(ai);

        setResponseTimeline(prev => [
            {
                time: new Date().toLocaleTimeString(),
                level: ai.risk_level || ai.level || "Unknown",
                actions: ai.actions || ai.recommendations || ["Threat analyzed"],
                escalation:
                    ai.risk_level === "Critical" ||
                    ai.risk_level === "High"
            },
            ...prev
        ]);

        setChatLog(prev => [
            ...prev,
            {
                role: "assistant",
                text:
                    ai.summary ||
                    ai.explanation ||
                    ai.analysis ||
                    response.reply ||
                    "Analysis complete."
            }
        ]);

        setUserInput("");

    } catch (err) {

        console.error(err);

        setChatLog(prev => [
            ...prev,
            {
                role: "assistant",
                text: err.message
            }
        ]);

    } finally {

        setChatLoading(false);

    }

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
<div
  style={{
    background: "rgba(17,24,39,.75)",
    borderRadius: 16,
    padding: 20,
    marginBottom: 25,
    border: "1px solid rgba(255,255,255,.08)"
  }}
>
  <h2 style={{ color: "#fff", marginBottom: 15 }}>
    🤖 Autonomous Response Timeline
  </h2>

  {responseTimeline.length === 0 ? (
    <p style={{ color: "#9ca3af" }}>
      Waiting for autonomous responses...
    </p>
  ) : (
    responseTimeline.map((item, index) => (
  <div
    key={index}
    style={{
      marginBottom: 15,
      padding: 12,
      background: "#111827",
      borderRadius: 8,
      borderLeft: "4px solid #00ffc8"
    }}
  >
    <div>
      <b>{item.time}</b>
    </div>

    <div style={{ marginTop: 6 }}>
      Threat Level:
      <span style={{ color: "#f97316", marginLeft: 6 }}>
        {item.level}
      </span>
    </div>

    <div style={{ marginTop: 8 }}>
      {item.actions?.map((action, i) => (
        <div key={i}>✅ {action}</div>
      ))}
    </div>

    {item.escalation && (
      <div
        style={{
          marginTop: 8,
          color: "#ef4444",
          fontWeight: "bold"
        }}
      >
        🚨 Escalated to SOC
      </div>
    )}
  </div>
))
  )}
</div>
<div
  style={{
    background: "rgba(17,24,39,.75)",
    borderRadius: 16,
    padding: 20,
    marginBottom: 25,
    border: "1px solid rgba(255,255,255,.08)"
  }}
>
  <h2 style={{ color: "#fff", marginBottom: 15 }}>
    🚨 Live Incident Queue
  </h2>

  <table
    style={{
      width: "100%",
      borderCollapse: "collapse",
      color: "#fff"
    }}
  >
    <thead>
      <tr>
        <th align="left">ID</th>
        <th align="left">Category</th>
        <th align="left">Score</th>
        <th align="left">Stage</th>
      </tr>
    </thead>

    <tbody>
      {graphData.nodes
        .slice()
        .reverse()
        .slice(0, 8)
        .map((node) => (
          <tr
            key={node.id}
            style={{
              borderTop: "1px solid #334155"
            }}
          >
            <td>{node.id}</td>

            <td>{node.category}</td>

            <td
              style={{
                color:
                  node.score >= 90
                    ? "#ef4444"
                    : node.score >= 75
                    ? "#f97316"
                    : node.score >= 50
                    ? "#facc15"
                    : "#22c55e"
              }}
            >
              {node.score}
            </td>

            <td>{node.stage}</td>
          </tr>
        ))}
    </tbody>
  </table>
</div>

<div
  style={{
    background: "rgba(17,24,39,.75)",
    borderRadius: 16,
    padding: 20,
    marginBottom: 25,
    border: "1px solid rgba(255,255,255,.08)"
  }}
>
  <h2 style={{ color: "#fff", marginBottom: 15 }}>
    🌍 Global Attack Map
  </h2>

  <AttackMap nodes={graphData.nodes} />
</div>{/* THREAT INTELLIGENCE / IOC SECTION */}
<div
  style={{
    background: "rgba(17,24,39,.75)",
    borderRadius: 16,
    padding: 20,
    marginBottom: 25,
    border: "1px solid rgba(255,255,255,.08)"
  }}
>
  <h2 style={{ color: "#fff", marginBottom: 15 }}>
    🧬 Threat Intelligence (IOCs)
  </h2>

  <table
    style={{
      width: "100%",
      color: "#fff",
      borderCollapse: "collapse"
    }}
  >
    <thead>
      <tr>
        <th align="left">Indicator</th>
        <th align="left">Category</th>
        <th align="left">Score</th>
        <th align="left">Confidence</th>
        <th align="left">Sightings</th>
      </tr>
    </thead>

    <tbody>
      {iocs.map((ioc) => (
        <tr key={ioc.id}>
          <td>{ioc.indicator}</td>
          <td>{ioc.category}</td>
          <td>{ioc.score}</td>
          <td>{ioc.confidence}%</td>
          <td>{ioc.sightings}</td>
        </tr>
      ))}
    </tbody>
  </table>
</div>

{/* THREAT DNA SECTION */}
<div
  style={{
    marginTop: 25,
    marginBottom: 25,
    padding: 20,
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: 12
  }}
>
  <h2 style={{ color: "#00ffc8", marginBottom: 15 }}>
    🧬 Threat DNA
  </h2>

  {threatDNA.length === 0 ? (
    <p style={{ color: "#94a3b8" }}>
      No Threat DNA fingerprints detected yet.
    </p>
  ) : (
    threatDNA.map((dna) => {
      const latestEvent =
  dna.events?.[dna.events.length - 1] || dna;

      return (
        <div
          key={dna.fingerprint}
          style={{
            marginBottom: 15,
            padding: 16,
            background: "#020617",
            border: "1px solid #334155",
            borderRadius: 10
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 12
            }}
          >
            <h3 style={{ color: "#38bdf8", margin: 0 }}>
              🧬 {dna.fingerprint}
            </h3>

            <span
              style={{
                padding: "5px 10px",
                borderRadius: 6,
                background:
                  dna.risk_band === "HIGH"
                    ? "#7f1d1d"
                    : dna.risk_band === "MEDIUM"
                    ? "#854d0e"
                    : "#14532d",
                color: "#fff",
                fontWeight: "bold",
                fontSize: 12
              }}
            >
              {dna.risk_band || "UNKNOWN"}
            </span>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(auto-fit, minmax(180px, 1fr))",
              gap: 10,
              color: "#cbd5e1"
            }}
          >
            <div>
              <b>Category:</b>
              <br />
              {dna.category || "-"}
            </div>

            <div>
              <b>MITRE:</b>
              <br />
              {dna.mitre || "-"}
            </div>

            <div>
              <b>Occurrences:</b>
              <br />
              {dna.occurrences ?? 0}
            </div>

            <div>
              <b>First Seen:</b>
              <br />
              {dna.first_seen || "-"}
            </div>

            <div>
              <b>Last Seen:</b>
              <br />
              {dna.last_seen || "-"}
            </div>
          </div>

          <div
            style={{
              marginTop: 15,
              padding: 12,
              background: "#0f172a",
              borderRadius: 8
            }}
          >
            <b style={{ color: "#00ffc8" }}>
              Behavioral Signature
            </b>

            <pre
              style={{
                marginTop: 8,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                color: "#94a3b8",
                fontSize: 12
              }}
            >
              {latestEvent.behavior_signature ??
                latestEvent.behavioral_signature ??
                latestEvent.signature ??
                "No behavioral signature available"}
            </pre>
          </div>

          <div
            style={{
              marginTop: 12,
              padding: 12,
              background: "#0f172a",
              borderRadius: 8
            }}
          >
            <b style={{ color: "#00ffc8" }}>
              IOC Profile
            </b>

            <pre
              style={{
                marginTop: 8,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                color: "#94a3b8",
                fontSize: 12
              }}
            >
              {JSON.stringify(
                latestEvent.iocs ??
                  latestEvent.ioc_profile ??
                  {},
                null,
                2
              )}
            </pre>
          </div>
        </div>
      );
    })
  )}
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
      }, 700);
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
{aiSummary?.campaign && (
  <div className="ai-card">
    <h3>🎯 Attack Campaign Intelligence</h3>

    <p>
      <b>Campaign:</b> {aiSummary.campaign}
    </p>

    <p>
      <b>Confidence:</b> {aiSummary.campaign_confidence}%
    </p>

    <p>
      <b>Description:</b> {aiSummary.campaign_description}
    </p>
  </div>
)}
<SOCAssistant />
{aiSummary?.attack_story && (
  <div className="ai-card">
    <h3>📖 Attack Narrative</h3>
    <p>{aiSummary.attack_story}</p>
  </div>
)}
<div
  style={{
    background: "#0f172a",
    padding: 12,
    borderRadius: 8,
    marginBottom: 15,
    color: "#d1d5db",
    lineHeight: 1.7
  }}
>
  {aiSummary.attack_story}
</div>

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
<hr style={{ margin: "15px 0", borderColor: "#334155" }} />

<h4 style={{ color: "#60a5fa" }}>
  📖 AI Attack Narrative
</h4>

<div
  style={{
    background: "#0f172a",
    padding: 12,
    borderRadius: 8,
    color: "#d1d5db",
    lineHeight: 1.8,
    marginBottom: 15
  }}
>
  {aiSummary.attack_story}
</div>
<hr style={{ margin: "15px 0", borderColor: "#334155" }} />

<h4 style={{ color: "#facc15" }}>
  🛡 MITRE ATT&CK Timeline
</h4>

<div
  style={{
    display: "flex",
    flexDirection: "column",
    gap: 10,
    marginBottom: 20
  }}
>
  {aiSummary.mitre_timeline?.map((item, i) => (
    <div
      key={i}
      style={{
        background: "#0f172a",
        padding: 10,
        borderRadius: 8,
        borderLeft: "4px solid #facc15"
      }}
    >
      <div style={{ color: "#fff", fontWeight: "bold" }}>
        {item.stage}
      </div>

      <div style={{ color: "#9ca3af" }}>
        {item.technique}
      </div>

      <div style={{ color: "#22c55e" }}>
        Risk Score: {item.score}
      </div>
    </div>
  ))}
</div>
<h4 style={{ color: "#38bdf8", marginTop: 20 }}>
    🛡 MITRE ATT&CK Timeline
</h4>

<div
  style={{
    marginTop: 10,
    marginBottom: 20
  }}
>
  {aiSummary.mitre_timeline?.map((step, index) => (
    <div
      key={index}
      style={{
        display: "flex",
        justifyContent: "space-between",
        padding: 10,
        marginBottom: 8,
        borderRadius: 8,
        background: "#0f172a",
        borderLeft: "4px solid #38bdf8"
      }}
    >
      <div>
        <b>{step.id}</b>
      </div>

      <div>{step.stage}</div>

      <div>{step.technique}</div>

      <div
        style={{
          color:
            step.score >= 85
              ? "#ef4444"
              : step.score >= 70
              ? "#f97316"
              : "#22c55e"
        }}
      >
        {step.score}
      </div>
    </div>
  ))}
</div>

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
{campaign && (
  <>
    <hr style={{ margin: "20px 0", borderColor: "#334155" }} />

    <h4 style={{ color: "#38bdf8" }}>
      🎯 Attack Campaign
    </h4>

    <div
      style={{
        background: "#0f172a",
        padding: 12,
        borderRadius: 8,
        marginTop: 10
      }}
    >
      <p>
        <b>Campaign ID:</b> {campaign.campaign_id}
      </p>

      <p>
        <b>Incidents:</b> {campaign.incident_count}
      </p>

      <p>
        <b>Patient Zero:</b> {campaign.patient_zero?.id}
      </p>

      <p>
        <b>Category:</b> {campaign.patient_zero?.category}
      </p>

      <p>
        <b>Highest Risk:</b> {campaign.highest_risk?.id}
      </p>

      <p>
        <b>Risk Score:</b> {campaign.highest_risk?.score}
      </p>

      <p>
        <b>MITRE:</b> {campaign.highest_risk?.mitre}
      </p>
    </div>
  </>
)}
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
{playbackIndex >= 0 &&
 replayData[replayIndex]?.nodes?.[playbackIndex] && (

<div
  style={{
    background:"#0f172a",
    border:"1px solid #00ffff",
    borderRadius:10,
    padding:15,
    marginBottom:15
  }}
>
  <h3 style={{color:"#00ffff"}}>
    ▶ Replay Event {playbackIndex + 1}
  </h3>

  <p>
    <b>Node:</b>{" "}
    {replayData[replayIndex].nodes[playbackIndex].id}
  </p>

  <p>
    <b>Category:</b>{" "}
    {replayData[replayIndex].nodes[playbackIndex].category}
  </p>

  <p>
    <b>MITRE:</b>{" "}
    {replayData[replayIndex].nodes[playbackIndex].mitre}
  </p>

  <p>
    <b>Stage:</b>{" "}
    {replayData[replayIndex].nodes[playbackIndex].stage}
  </p>

  <p>
    <b>Risk:</b>{" "}
    {replayData[replayIndex].nodes[playbackIndex].score}
  </p>

</div>

)}
          <ForceGraph2D
  ref={graphRef}
  graphData={graphData}
linkSource="source"
linkTarget="target"
linkDirectionalParticles={(link) => {
  const target =
    typeof link.target === "object"
      ? link.target.id
      : link.target;

  return playbackIndex >= 0 ? 4 : 2;
}}

linkDirectionalParticleWidth={(link) => {
  return playbackIndex >= 0 ? 4 : 2;
}}

linkDirectionalParticleSpeed={(link) => 0.006}
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

  linkDirectionalArrowLength={8}
  linkDirectionalArrowRelPos={1}
  linkCurvature={0.25}

  linkLabel={(link) =>
  link.relation || "attack_chain"
}

  nodeLabel={(node) =>
    `${node.id}
${node.category}
Stage: ${node.stage || "Unknown"}
Risk: ${node.score}
MITRE: ${node.mitre || "Unknown"}`
  }

  nodeColor={(node) => {

  const current =
    replayData[replayIndex]?.nodes?.[playbackIndex];

  if (current && current.id === node.id) {
    return "#00ffff";
  }

  if (node.score >= 90) return "#ff0000";
  if (node.score >= 75) return "#ff7a00";
  if (node.score >= 50) return "#ffd400";

  return "#00ff88";
}}

  nodeVal={(node) => {

  const current =
    replayData[replayIndex]?.nodes?.[playbackIndex];

  if (current && current.id === node.id) {
    return 16;
  }

  return Math.max(4, (node.score || 10) / 5);
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

  ctx.fillText(
    `${node.category || "Threat"} | ${node.stage || "Unknown"}`,
    node.x + size + 2,
    node.y + size + 2
);
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
</div>
      
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
    </div>
  );
}
