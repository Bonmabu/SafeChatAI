import React from "react";

export default function ComplianceDashboard({ compliance }) {
  if (!compliance) return null;

  const controls = compliance.controls || {
    implemented: 0,
    pending: 0,
  };

  return (
    <div
      style={{
        background: "#111827",
        color: "white",
        padding: 20,
        borderRadius: 12,
        marginTop: 20,
      }}
    >
      <h2>🛡 Compliance Center</h2>

      <p>
        <strong>Status:</strong> {compliance.status}
      </p>

      <p>
        <strong>Compliance Score:</strong> {compliance.score}%
      </p>

      <p>
        <strong>Implemented Controls:</strong> {controls.implemented}
      </p>

      <p>
        <strong>Pending Controls:</strong> {controls.pending}
      </p>
    </div>
  );
}