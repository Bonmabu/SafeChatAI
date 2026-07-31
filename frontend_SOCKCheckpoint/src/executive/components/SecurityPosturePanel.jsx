import React from "react";
import "./SecurityPosturePanel.css";

export default function SecurityPosturePanel({
  posture = {}
}) {

  const score = posture.security_score ?? 0;

  const getRiskClass = () => {
    if (score >= 80) return "risk-critical";
    if (score >= 60) return "risk-high";
    if (score >= 40) return "risk-medium";
    return "risk-low";
  };

  return (
    <div className="security-posture-panel">

      <div className="security-posture-header">

        <h2>🛡 Security Posture</h2>

        <div className={`posture-score ${getRiskClass()}`}>
          {score}%
        </div>

      </div>

      <div className="posture-grid">

        <div className="posture-card">
          <h4>Threat Level</h4>
          <div className="posture-value">
            {posture.threat_level ?? "UNKNOWN"}
          </div>
        </div>

        <div className="posture-card">
          <h4>Active Incidents</h4>
          <div className="posture-value">
            {posture.active_incidents ?? 0}
          </div>
        </div>

        <div className="posture-card">
          <h4>Protected Assets</h4>
          <div className="posture-value">
            {posture.protected_assets ?? 0}
          </div>
        </div>

        <div className="posture-card">
          <h4>AI Risk Prediction</h4>
          <div className="posture-value">
            {posture.risk_prediction ?? "UNKNOWN"}
          </div>
        </div>

        <div className="posture-card">
          <h4>Critical Threats</h4>
          <div
            className="posture-value"
            style={{ color: "#ef4444" }}
          >
            {posture.critical_threats ?? 0}
          </div>
        </div>

        <div className="posture-card">
          <h4>SOC Health</h4>
          <div className="posture-value">
            {posture.soc_health ?? 0}%
          </div>
        </div>

        <div className="posture-card">
          <h4>Enterprise Status</h4>
          <div
            className="posture-value"
            style={{
              color: posture.color || "#22c55e",
              fontWeight: "bold"
            }}
          >
            {posture.enterprise_status ?? "UNKNOWN"}
          </div>
        </div>

      </div>

      <div className="posture-bar">

        <div
          className={`posture-progress ${getRiskClass()}`}
          style={{
            width: `${score}%`
          }}
        />

      </div>

    </div>
  );
}