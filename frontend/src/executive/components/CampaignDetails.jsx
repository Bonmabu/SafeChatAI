import React from "react";

export default function CampaignDetails() {
  return (
    <div
      style={{
        marginTop: 25,
        background: "#111827",
        border: "1px solid #334155",
        borderRadius: 16,
        padding: 20,
        color: "#fff"
      }}
    >
      <h2 style={{ color: "#00ffc8" }}>
        🎯 Campaign Details
      </h2>

      <p style={{ color: "#94a3b8" }}>
        No active campaign selected.
      </p>
    </div>
  );
}