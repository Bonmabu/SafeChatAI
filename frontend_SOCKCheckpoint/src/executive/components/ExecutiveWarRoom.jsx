import { useEffect, useState } from "react";
import "./ExecutiveWarRoom.css";
export default function ExecutiveWarRoom({
  summary,
  decision,
  attackBurst,
  escalation,
  loading,
  message,
  onDeclareIncident,
  onCrisisMode,
  onNotifyBoard,
  onGenerateReport
}) {
const [countdown, setCountdown] = useState(1800);

const [decisionHistory, setDecisionHistory] = useState([]);

useEffect(() => {
    const timer = setInterval(() => {
        setCountdown((s) => (s > 0 ? s - 1 : 0));
    }, 1000);

    return () => clearInterval(timer);
}, []);

const minutes = Math.floor(countdown / 60);
const seconds = countdown % 60;
  const risk =
    decision?.enterprise_risk ??
    summary?.security_score ??
    0;

  const status = attackBurst?.burst
    ? "CRISIS"
    : (decision?.level ?? "NORMAL");

  const statusColor =
    status === "CRISIS"
      ? "#ef4444"
      : status === "HIGH"
      ? "#f97316"
      : "#22c55e";

  return (
    <div className="warroom">
<div className="executive-kpis">

<div className="kpi">
<h4>Security Score</h4>
<h2>{summary?.security_score ?? 0}%</h2>
</div>

<div className="kpi">
<h4>Enterprise Risk</h4>
<h2>{risk}</h2>
</div>

<div className="kpi">
<h4>Critical Threats</h4>
<h2>{summary?.critical_threats ?? 0}</h2>
</div>

<div className="kpi">
<h4>Recovery ETA</h4>
<h2>2h 15m</h2>
</div>

</div>
{status === "CRISIS" && (

<div className="crisis-banner">

🚨 ENTERPRISE CYBER EMERGENCY

<div>

Immediate executive action required.

</div>

</div>

)}

      <div className="warroom-header">
        <div>
          <h2>🎖 Executive War Room</h2>
          <p>Enterprise Security Command Center</p>
        </div>

        <div
          className="warroom-status"
          style={{ background: statusColor }}
        >
          {status}
        </div>
      </div>

      <div className="warroom-grid">

        <div className="war-card">
          <h4>Security Score</h4>
          <h1>{summary?.security_score ?? 0}%</h1>
        </div>

        <div className="war-card">
          <h4>Enterprise Risk</h4>
          <h1>{risk}</h1>
        </div>

        <div className="war-card">
          <h4>Risk Level</h4>
          <h1>{decision?.level ?? "Unknown"}</h1>
        </div>

        <div className="war-card">
          <h4>Critical Threats</h4>
          <h1>{summary?.critical_threats ?? 0}</h1>
        </div>

      </div>

      <div className="impact-grid">

  <div className="impact-card">
    <h4>Estimated Financial Exposure</h4>
    <h2>$2.4M</h2>
  </div>

  <div className="impact-card">
    <h4>Critical Assets</h4>
    <h2>18</h2>
  </div>

  <div className="impact-card">
    <h4>Affected Users</h4>
    <h2>127</h2>
  </div>

  <div className="impact-card">
    <h4>Business Units</h4>
    <h2>Finance</h2>
  </div>

</div>

<div
  style={{
    marginTop: 25,
    padding: 20,
    borderRadius: 12,
    background: "#0f172a",
    border: "1px solid #334155"
  }}
>
  <h3 style={{ color: "#00ffc8" }}>
    AI Executive Recommendation
  </h3>

  <p style={{ color: "#cbd5e1", lineHeight: 1.8 }}>
    {decision?.recommendation ??
      summary?.action ??
      "Monitor threat activity and review security controls."}
  </p>
</div>
        
      <div className="war-actions">

        <button
          className="danger"
          onClick={onDeclareIncident}
          disabled={loading}
        >
          🚨 Declare Incident
        </button>

        <button
          className="warning"
          onClick={onCrisisMode}
          disabled={loading}
        >
          ⚠ Crisis Mode
        </button>

        <button
          className="info"
          onClick={onNotifyBoard}
          disabled={loading}
        >
          📢 Notify Board
        </button>

        <button
          className="success"
          onClick={onGenerateReport}
          disabled={loading}
        >
          📄 Executive Report
        </button>

      </div>

      {loading && (
        <div
          style={{
            marginTop: 20,
            color: "#facc15",
            fontWeight: "bold"
          }}
        >
          Processing executive action...
        </div>
      )}

      {message && (
        <div
          style={{
            marginTop: 20,
            padding: 15,
            borderRadius: 10,
            background: "#0f172a",
            border: "1px solid #334155",
            color: "#22c55e"
          }}
        >
          {message}
        </div>
      )}

      {escalation && (
        <div
          style={{
            marginTop: 30,
            padding: 20,
            background: "#0f172a",
            borderRadius: 12,
            border: "1px solid #334155"
          }}
        >
          <h3 style={{ color: "#facc15" }}>
            Escalation Overview
          </h3>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
              gap: 15,
              marginTop: 15
            }}
          >
            <div>
              <strong>Critical</strong>
              <br />
              {escalation.critical}
            </div>

            <div>
              <strong>High</strong>
              <br />
              {escalation.high}
            </div>

            <div>
              <strong>Medium</strong>
              <br />
              {escalation.medium}
            </div>

            <div>
              <strong>Low</strong>
              <br />
              {escalation.low}
            </div>
          </div>

          <div style={{ marginTop: 20 }}>
  <strong>Containment Deadline</strong>

  <h2 style={{ color: "#00ffc8", marginTop: 10 }}>
    {minutes}:{seconds.toString().padStart(2, "0")}
  </h2>
</div>
        </div>
      )}

    </div>
  );
}