import axios from "axios";

axios.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");

  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }

  return config;
});
import Login from "./Login";
import ThreatMap from "./components/ThreatMap";
import { useEffect, useState, useRef } from "react";
import SOCHeader from "./components/soc/SOCHeader";
import KPICards from "./components/soc/KPICards";
import AttackGraph from "./components/soc/AttackGraph";
import IncidentTable from "./components/soc/IncidentTable";
import ThreatTimeline from "./components/soc/ThreatTimeline";
import MITREPanel from "./components/soc/MITREPanel";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from "recharts";

function App() {
  const [authenticated, setAuthenticated] = useState(
  !!localStorage.getItem("token")
);
  const [threatMap, setThreatMap] = useState([]);
  const [summary, setSummary] = useState(null);
  
  const [loading, setLoading] = useState(true);
  const graphRef = useRef();
  const [timeline, setTimeline] = useState([]);
  const [aiSummary, setAiSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [executive, setExecutive] = useState(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [assigneeFilter, setAssigneeFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("NEWEST");
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;
  
  const [graphData, setGraphData] = useState({
    nodes: [],
    links: []
  });
const [intel, setIntel] = useState([]);
const [selectedNode, setSelectedNode] = useState(null);
const [selectedIncident, setSelectedIncident] = useState(null);
const [mitreInfo, setMitreInfo] = useState(null);
const [reports, setReports] = useState([]);
const [analytics, setAnalytics] = useState(null);
const [highlightNodes, setHighlightNodes] = useState(new Set());
const [highlightLinks, setHighlightLinks] = useState(new Set());
const [huntQuery, setHuntQuery] = useState("");
const [huntResults, setHuntResults] = useState([]);

  const API_BASE = import.meta.env.VITE_API_BASE;
  const getRiskLevel = (score) => {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
};

useEffect(() => {
  loadData();

  const interval = setInterval(() => {
    loadData();
  }, 30000);

  return () => clearInterval(interval);
}, []);
const runThreatHunt = async () => {
  try {
    const res = await axios.get(
      `${API_BASE}/hunt`,
      {
        params: {
          query: huntQuery
        }
      }
    );

    setHuntResults(res.data);
  } catch (err) {
    console.error(err);
  }
};
useEffect(() => {
  console.log("GRAPH DATA:", graphData);
}, [graphData]);
useEffect(() => {
  if (graphRef.current && graphData.nodes.length > 0) {
    setTimeout(() => {
      graphRef.current.zoomToFit(400, 100);

      graphRef.current.centerAt(0, 0, 1000);

      graphRef.current.zoom(0.8, 1000);
    }, 500);
  }
}, [graphData]);
useEffect(() => {
  const ws = new WebSocket(
  `${import.meta.env.VITE_WS_BASE}/ws/soc`
);
  

  ws.onopen = () => {
    console.log("✅ WS CONNECTED");
  };

  ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  console.log("WS EVENT:", data);

  const type = data.type || data.event_type;
if (type === "new_threat") {

  const node = data.node;

  const countries = [
    ["Kenya",-1.286389,36.817223],
    ["USA",38.89511,-77.03637],
    ["China",39.9042,116.4074],
    ["Russia",55.7558,37.6176],
    ["Germany",52.52,13.405],
    ["Brazil",-15.793889,-47.882778],
    ["India",28.6139,77.2090],
    ["United Kingdom",51.5072,-0.1276],
    ["Japan",35.6895,139.6917],
    ["South Africa",-25.7461,28.1881]
  ];

  const random =
      countries[
          Math.floor(Math.random()*countries.length)
      ];

  setThreatMap(prev=>[
      {
          id:node.id,
          category:node.category,
          score:node.score,
          country:random[0],
          lat:random[1],
          lng:random[2]
      },
      ...prev
  ].slice(0,100));
}
if (type === "threat_intelligence") {

    setIntel(prev => {

        const exists = prev.find(
            x => x.indicator === data.data.indicator
        );

        if (exists) {
            return prev.map(x =>
                x.indicator === data.data.indicator
                    ? data.data
                    : x
            );
        }

        return [data.data, ...prev].slice(0, 20);
    });

    return;
}

  // LIVE KPI UPDATE
  if (type === "executive_dashboard") {

    setExecutive(data);

    return;
}

  // TIMELINE
  if (
    type === "alert_event" ||
    type === "auto_response_event" ||
    type === "ai_decision_event" ||
    type === "threat_intelligence" ||
    type === "new_threat"
  ) {
    setTimeline(prev => [
      {
        time: new Date().toLocaleTimeString(),
        event: type
      },
      ...prev
    ].slice(0, 25));
  }

  // REFRESH KPI CARDS
  if (
  type === "alert_event" ||
  type === "auto_response_event" ||
  type === "ai_decision_event" ||
  type === "new_threat"
) {
  loadData();
}

  // FULL GRAPH UPDATE
  if (type === "attack_graph") {

    const nodes = (data.nodes || []).map(node => ({
      id: String(node.id),
      category: node.category,
      score: Number(node.score || 0),
      riskLevel: getRiskLevel(
        Number(node.score || 0)
      )
    }));

    const links = (data.links || []).map(link => ({
      source: String(link.source),
      target: String(link.target)
    }));

    console.log("GRAPH UPDATE:", nodes.length, links.length);

    setGraphData({
      nodes,
      links
    });

    return;
  }

  // SINGLE NODE UPDATE
  if (type === "new_threat" && data.node) {
  const node = {
    id: String(data.node.id),
    category: data.node.category,
    score: Number(data.node.score),
    riskLevel: getRiskLevel(Number(data.node.score))
  };

  if (data.mitre) {
    setMitreInfo(data.mitre);

    setIncidents(prev => [
      {
        id: data.node.id,
        category: data.node.category,
        severity: data.node.riskLevel || "High Risk",
        score: data.node.score,
        latitude: data.node.latitude ?? (-1.28 + Math.random() * 30),
        longitude: data.node.longitude ?? (36.82 + Math.random() * 40)
      },
      ...prev
    ]);
  }

  setGraphData(prev => ({
    nodes: [...prev.nodes, node],
    links: prev.links
  }));

  return;   // 🔍¥ ADD THIS (important)
}
};
  ws.onerror = (err) => {
    console.error("❌ WS ERROR", err);
  };

  ws.onclose = () => {
    console.log("WS CLOSED");
  };

  return () => ws.close();
}, []);
  const loadData = async () => {
  try {
    setLoading(true);

    const summaryRes = await axios.get(
  `${API_BASE}/executive/dashboard`
);
const reportsRes = await axios.get(
  `${API_BASE}/reports`
);
const analyticsRes = await axios.get(
  `${API_BASE}/analytics`
);

console.log("REPORTS:", reportsRes.data);
const incidentsRes = await axios.get(
  `${API_BASE}/incidents`
);

setIncidents(incidentsRes.data);
setReports(reportsRes.data);
setAnalytics(analyticsRes.data);

    const graphRes = await axios.get(
      `${API_BASE}/attack-graph`
    );
if (!aiSummary) {
  const aiRes = await axios.post(
    `${API_BASE}/soc-ai`,
    {
      query: "incident threat pattern health"
    }
  );

  setAiSummary(aiRes.data.analysis);
}
console.log("GRAPH RESPONSE");
console.log(graphRes.data);

    setSummary(summaryRes.data);

    console.log("GRAPH API:", graphRes.data);

    const rawNodes = graphRes.data?.nodes || [];
const rawEdges = graphRes.data?.links || [];

const nodes = rawNodes.map(node => {
  const score = Number(node.score ?? node.max_score ?? 0);

  return {
    id: String(node.id),
    category: node.category || "Unknown",
    score,
    riskLevel: getRiskLevel(score)
  };
});

const links = rawEdges.map(edge => ({
  source: String(edge.source),
  target: String(edge.target)
}));

console.log("PARSED NODES:", nodes);
console.log("PARSED LINKS:", links);

const cleanNodes = nodes.filter(
  n => n.id && n.id !== "None"
);

const nodeIds = new Set(
  cleanNodes.map(n => String(n.id))
);

const cleanLinks = links.filter(
  l =>
    l.source &&
    l.target &&
    l.source !== "None" &&
    l.target !== "None" &&
    nodeIds.has(String(l.source)) &&
    nodeIds.has(String(l.target))
);

console.log("CLEAN GRAPH NODES", cleanNodes.length);
console.log("CLEAN GRAPH LINKS", cleanLinks.length);

setGraphData({
  nodes: cleanNodes,
  links: cleanLinks
});

console.log("GRAPH STATE UPDATED");
  } catch (err) {
    console.error(err);
  } finally {
    setLoading(false);
  }
};
const resolveIncident = async (id) => {
  await axios.put(`${API_BASE}/incidents/${id}/resolve`);
  loadData();
};

const investigateIncident = async (id) => {
  await axios.put(`${API_BASE}/incidents/${id}/investigate`);
  loadData();
};

const assignIncident = async (id) => {
  const analyst = prompt("Assign analyst:");

  if (!analyst) return;

  await axios.put(
    `${API_BASE}/incidents/${id}/assign`,
    {
      assigned_to: analyst
    }
  );

  loadData();
};

  const chartData = [
    { name: "Scans", value: summary?.total_scans || 0 },
    { name: "Alerts", value: summary?.total_alerts || 0 },
    { name: "Incidents", value: summary?.total_incidents || 0 },
    { name: "Open", value: summary?.open_incidents || 0 }
  ];
  if (!authenticated) {
  return (
    <Login
      onLogin={() => {
        console.log("LOGIN CALLBACK FIRED");
        console.log("TOKEN:", localStorage.getItem("token"));
        console.log("ROLE:", localStorage.getItem("role"));
        setAuthenticated(true);
      }}
    />
  );
}

return (
<>
<nav style={{display:"flex",alignItems:"center",gap:"24px",padding:"14px 20px",background:"#020617",borderBottom:"1px solid #1e293b",marginBottom:"10px"}}>
<strong style={{color:"#00ffc8",fontSize:"18px"}}>SafeChat AI SOC</strong>
<a href="/dashboard/overview">Overview</a>
<a href="/dashboard/customer">Customer SOC</a>
<a href="/dashboard/campaigns">Campaigns</a>
<a href="/dashboard/executive">Executive / IT</a>
<a href="/dashboard/admin">Admin SOC</a>
<button onClick={()=>{localStorage.removeItem("token");localStorage.removeItem("role");window.location.href="/";}} style={{marginLeft:"auto",background:"transparent",border:"1px solid #334155",color:"#f8fafc",padding:"8px 14px",borderRadius:"8px",cursor:"pointer"}}>Login</button>
</nav>
<divv
style={{
background:"#0f172a",
color:"#f8fafc",
minHeight:"100vh",
padding:"8px",
fontFamily:"Arial",
overflow:"hidden"
}}
>

<style>
{`
h1,h2,h3,h4 {
 color:#f8fafc;
}

table th {
 color:#38bdf8;
}

table td {
 color:#e2e8f0;
}
`}
</style>

      <div
  style={{
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 20
  }}
>
  <SOCHeader
  onLogout={() => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    setAuthenticated(false);
  }}
/>

  
</div>

      {summary && (
<div style={{marginBottom:"5px"}}>
<KPICards summary={summary}/>
</div>
)}

      <div
  style={{
    display: "flex",
    flexDirection: "column",
    gap: "15px",
    marginTop: "15px"
  }}
>

  <div
  style={{
    display:"grid",
    gridTemplateColumns:"2.5fr 1fr",
    gap:"15px",
    marginTop:"15px"
  }}
>

  {/* LARGE ATTACK GRAPH */}
  <div
    style={{
      background:"#111827",
      borderRadius:12,
      padding:10,
      height:"500px",
      overflow:"hidden",
      minWidth:0,
      border:"1px solid #1e293b"
    }}
  >

    <AttackGraph
      graphRef={graphRef}
      graphData={graphData}
      selectedNode={selectedNode}
      setSelectedNode={setSelectedNode}
      highlightNodes={highlightNodes}
      setHighlightNodes={setHighlightNodes}
      highlightLinks={highlightLinks}
      setHighlightLinks={setHighlightLinks}
    />

  </div>


  {/* SMALL SOC METRICS */}
  <div
    style={{
      background:"#0b1220",
      border:"1px solid #1f2937",
      borderRadius:10,
      padding:10,
      height:"500px"
    }}
  >

    <h2 style={{color:"#38bdf8"}}>
      📈 SOC Metrics
    </h2>

    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3"/>
        <XAxis dataKey="name"/>
        <YAxis/>
        <Tooltip/>
        <Line 
          type="monotone"
          dataKey="value"
        />
      </LineChart>
    </ResponsiveContainer>

  </div>

</div>
<div
style={{
  display:"grid",
  gridTemplateColumns:"1fr",
  gap:"10px",
  marginTop:10
}}
>
  <div
  style={{
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 15
  }}
>
  
<IncidentTable
  incidents={incidents}
  search={search}
  setSearch={setSearch}
  severityFilter={severityFilter}
  setSeverityFilter={setSeverityFilter}
  assigneeFilter={assigneeFilter}
  setAssigneeFilter={setAssigneeFilter}
  sortBy={sortBy}
  setSortBy={setSortBy}
  currentPage={currentPage}
  setCurrentPage={setCurrentPage}
  pageSize={pageSize}
  resolveIncident={resolveIncident}
  investigateIncident={investigateIncident}
  assignIncident={assignIncident}
  setSelectedIncident={setSelectedIncident}
/>
</div>
</div>
<ThreatTimeline
  timeline={timeline}
  currentPage={currentPage}
  setCurrentPage={setCurrentPage}
  incidents={incidents}
  pageSize={pageSize}
/>
{executive && (
  <div
    style={{
      marginTop: 10,
      background: "#111827",
      borderRadius: 10,
      padding: 10
    }}
  >
    <h2
style={{
  color:"#ffffff",
  fontWeight:"700"
}}
>
🤖 AI Threat Intelligence
</h2>

    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(3,1fr)",
        gap: 15
      }}
    >
      <div>
        <h4>Threat Pressure</h4>
        <h2>{executive.ai.threat_pressure_index}</h2>
      </div>

      <div>
        <h4>Instability Score</h4>
        <h2>{executive.ai.instability_score}</h2>
      </div>

      <div>
        <h4>Executive Decision</h4>
        <h2>{executive.ai.executive_decision}</h2>
      </div>
    </div>

    <hr style={{ margin: "20px 0" }} />

    <p>
      <b>Breach Forecast:</b>{" "}
      {executive.intelligence.forecast.breach_probability}
    </p>

    <p>
      <b>Prediction Window:</b>{" "}
      {executive.intelligence.forecast.time_window}
    </p>

    <p>
      <b>Trend:</b>{" "}
      {executive.intelligence.forecast.trend}
    </p>
  </div>
)}
<MITREPanel mitreInfo={mitreInfo} />
{aiSummary && (
  <div
    style={{
      marginTop: 10,
      background: "#111827",
      borderRadius: 10,
      padding: 10,
      border: "1px solid #334155"
    }}
  >
    <h2
style={{
  color:"#ffffff",
  fontWeight:"700"
}}
>
🧠  AI SOC Analyst
</h2>

    <div
      style={{
        marginTop: 15,
        background: "#1f2937",
        padding: 15,
        borderRadius: 8
      }}
    >
      <h3>Threat Assessment</h3>

      {(aiSummary?.insights || []).map((item, index) => (
        <div
          key={index}
          style={{
            padding: "8px 0",
            borderBottom: "1px solid #374151"
          }}
        >
          ✅ {item}
        </div>
      ))}
    </div>

    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(2,1fr)",
        gap: 15,
        marginTop: 10
      }}
    >
      <div
        style={{
          background: "#0f172a",
          padding: 15,
          borderRadius: 8
        }}
      >
        <h4>AI Confidence</h4>
        <h2 style={{ color: "#22c55e" }}>96%</h2>
      </div>

      <div
        style={{
          background: "#0f172a",
          padding: 15,
          borderRadius: 8
        }}
      >
        <h4>Recommendation</h4>

        <p>
          Continue monitoring attack behavior and
          automatically escalate repeated high-risk
          threats.
        </p>
      </div>
    </div>
  </div>
)}
      
      <div
        style={{
          marginTop: 10,
          background: "#111827",
          borderRadius: 10,
          padding: 10
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 15
          }}
        >
          <h2
style={{
  color:"#ffffff",
  fontWeight:"700"
}}
>
📄 Incident Reports
</h2>

          <div>
            <button onClick={async () => {
                const response = await axios.get(
                  `${API_BASE}/reports/pdf`,
                  { responseType: "blob" }
                );

                const url = URL.createObjectURL(response.data);
                const link = document.createElement("a");
                link.href = url;
                link.download = "incident_report.pdf";
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
              }}>
              📄 PDF
            </button>

            <button
              style={{ marginLeft: 10 }}
              onClick={async () => {
                const response = await axios.get(
                  `${API_BASE}/reports/csv`,
                  { responseType: "blob" }
                );

                const url = URL.createObjectURL(response.data);
                const link = document.createElement("a");
                link.href = url;
                link.download = "incident_report.csv";
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
              }}
            >
              📊 CSV
            </button>
          </div>
        </div>

        <table style={{ width: "100%" }}>
          <thead>
            <tr>
              <th>ID</th>
              <th>Date</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Assigned</th>
            </tr>
          </thead>

          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td>{r.id}</td>
                <td>{r.created_at}</td>
                <td>{r.category}</td>
                <td>{r.severity}</td>
                <td>{r.status}</td>
                <td>{r.assigned_to || "Unassigned"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
<div
  style={{
    marginTop: 10,
    background: "#111827",
    borderRadius: 10,
    padding: 10
  }}
>
  <h2
style={{
  color:"#ffffff",
  fontWeight:"700"
}}
>
🎯 Threat Hunting Workspace
</h2>

  <div
    style={{
      display: "flex",
      gap: 10,
      marginBottom: 15
    }}
  >
    <input
      value={huntQuery}
      onChange={(e) => setHuntQuery(e.target.value)}
      placeholder="Search malware, phishing, ransomware..."
      style={{
        flex: 1,
        padding: 10,
        borderRadius: 6,
        background: "#1f2937",
        color: "white",
        border: "1px solid #374151"
      }}
    />

    <button onClick={runThreatHunt}>
      Hunt
    </button>
  </div>

  <table style={{ width: "100%" }}>
    <thead>
      <tr>
        <th>ID</th>
        <th>Category</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Message</th>
      </tr>
    </thead>

    <tbody>
      {huntResults.map((item) => (
        <tr key={item.id}>
          <td>{item.id}</td>
          <td>{item.category}</td>
          <td>{item.severity}</td>
          <td>{item.status}</td>
          <td>{item.message}</td>
        </tr>
      ))}
    </tbody>
  </table>
</div>
{selectedIncident && (
  <div
    style={{
      marginTop: 10,
      background: "#0f172a",
      borderRadius: 10,
      padding: 10,
      border: "1px solid #334155"
    }}
  >
    <h2>🕵️ Investigation Workspace</h2>

    <div
      style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: 20
      }}
    >
      <div>
        <p><b>Incident ID:</b> {selectedIncident.id}</p>

        <p><b>Category:</b> {selectedIncident.category}</p>

        <p><b>Severity:</b> {selectedIncident.severity}</p>

        <p><b>Status:</b> {selectedIncident.status}</p>

        <p><b>Assigned:</b> {selectedIncident.assigned_to || "Unassigned"}</p>

        <p><b>Created:</b> {selectedIncident.created_at}</p>
      </div>

      <div>
        <h3>AI Investigation Notes</h3>

        <p>
          This incident appears related to
          <b> {selectedIncident.category}</b>.
        </p>

        <p>
  Recommended next action:
  Validate the IOC, inspect related alerts,
  and determine whether lateral movement
  has occurred.
</p>

<hr style={{ margin: "20px 0" }} />

<h3>Evidence Collected</h3>

<table
  style={{
    width: "100%",
    borderCollapse: "collapse"
  }}
>
  <thead>
    <tr>
      <th>Type</th>
      <th>Value</th>
    </tr>
  </thead>

  <tbody>
    {(selectedIncident.iocs || []).length === 0 ? (
      <tr>
        <td colSpan="2">
          No IOC evidence available
        </td>
      </tr>
    ) : (
      selectedIncident.iocs.map((ioc, index) => (
        <tr key={index}>
          <td>{ioc.type}</td>
          <td>{ioc.value}</td>
        </tr>
      ))
    )}
  </tbody>
</table>
        
      </div>
    </div>

    <div
      style={{
        marginTop: 10,
        display: "flex",
        gap: 10
      }}
    >
      <button onClick={() => assignIncident(selectedIncident.id)}>
        👤 Assign
      </button>

      <button onClick={() => investigateIncident(selectedIncident.id)}>
        🔍 Investigate
      </button>

      <button onClick={() => resolveIncident(selectedIncident.id)}>
        ✅ Resolve
      </button>

      <button onClick={() => setSelectedIncident(null)}>
        ❌ Close
      </button>
    </div>
  </div>
)}

      {analytics && (
  <div
    style={{
      marginTop: 10,
      background: "#111827",
      borderRadius: 10,
      padding: 10
    }}
  >
    <h2
      style={{
        color: "#ffffff",
        fontWeight: "700"
      }}
    >
      📊 Security Analytics
    </h2>

    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(3,1fr)",
        gap: 20
      }}
    >

      <div>
        <h3>Threat Categories</h3>

        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={analytics.categories}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="count" />
          </BarChart>
        </ResponsiveContainer>
      </div>


      <div>
        <h3>Severity Distribution</h3>

        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie
              data={analytics.severities}
              dataKey="count"
              nameKey="name"
              outerRadius={80}
              label
            >
              {analytics.severities.map((_, index) => (
                <Cell key={index} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>


      <div>
        <h3>Status Overview</h3>

        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={analytics.statuses}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="count" />
          </BarChart>
        </ResponsiveContainer>
      </div>


    </div>
  </div>
)}
</div>
</div>
);
}

export default App;
