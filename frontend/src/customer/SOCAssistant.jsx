import { useState } from "react";
import axios from "axios";

const API =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function SOCAssistant() {

  const [message, setMessage] = useState("");
  const [response, setResponse] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  async function askAI() {
  if (!message.trim()) return;

  try {
    setLoading(true);

    const incidents = await axios.get(`${API}/customer/incidents`, {
  params: { tenant_id: "demo" }
});
    console.log(incidents.data);
    const alerts = await axios.get(`${API}/alerts`);

    console.log("INCIDENTS =", incidents.data);
    console.log("ALERTS =", alerts.data);

    const incidentList = incidents.data || [];

    const alertList = Array.isArray(alerts.data)
  ? alerts.data
  : alerts.data.data || [];

    const payload = {
      query: message,

      nodes: incidentList.map((item) => ({
  id: `incident-${item.id}`,
  category: item.category || "Unknown",
  score:
    Number(item.risk_score) ||
    (item.severity === "Critical" ? 95 :
     item.severity === "High Risk" ? 85 :
     item.severity === "Medium Risk" ? 60 : 30),

  stage: item.stage || "Initial Access",
  mitre: item.mitre || "T1566 - Phishing"
})),

      alerts: alertList.map((a) => ({
        id: a.id,
        message: a.message,
        severity: a.severity || a.level || "Medium"
      }))
    };

    console.log("SOC PAYLOAD =", payload);
    console.log("INCIDENT COUNT =", incidentList.length);
    console.log("PAYLOAD =", payload);

    const res = await axios.post(`${API}/soc-chat`, {
  query: message
});

    console.log("SOC RESPONSE =", res.data);

    setResponse(res.data.answer);
    setResults(res.data.results || []);

  } catch (err) {
    console.error("SOC AI ERROR:", err.response?.data || err);
    setResponse("SOC AI analysis failed.");
  } finally {
    setLoading(false);
  }
}

  return (
    <div className="ai-card">

      <h3>🤖 SOC AI Analyst</h3>

      <textarea
        placeholder="Ask SOC AI about threats, incidents, response..."
        value={message}
        onChange={(e)=>setMessage(e.target.value)}
      />

      <button onClick={askAI}>
        {loading ? "Analyzing..." : "Ask AI"}
      </button>


      {response && (
        <div>
          <h4>AI Response</h4>
          <p>{response}</p>
{results.length > 0 && (
  <table style={{ width: "100%", marginTop: 10 }}>
    <thead>
      <tr>
        <th>ID</th>
        <th>Category</th>
        <th>Status</th>
        <th>Risk</th>
      </tr>
    </thead>

    <tbody>
      {results.map((r) => (
        <tr key={r.id}>
          <td>{r.id}</td>
          <td>{r.category}</td>
          <td>{r.status}</td>
          <td>{r.risk_score}</td>
        </tr>
      ))}
    </tbody>
  </table>
)}
        </div>
      )}

    </div>
  );
}