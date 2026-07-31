import React from "react";
import "./ThreatHeatMap.css";

export default function ThreatHeatMap({ threatMatrix = {} }) {

  const rows = [
    { name: "Finance", value: threatMatrix.critical || 0 },
    { name: "Identity", value: threatMatrix.high || 0 },
    { name: "Cloud", value: threatMatrix.medium || 0 },
    { name: "Endpoints", value: threatMatrix.low || 0 },
    { name: "Email", value: (threatMatrix.high || 0) + 2 },
    { name: "Servers", value: (threatMatrix.critical || 0) + 1 }
  ];

  const max = Math.max(...rows.map(r => r.value), 1);

  return (
    <section className="threat-heatmap">

      <h2>🔥 Enterprise Threat Heat Map</h2>

      {rows.map(row => (
        <div className="heat-row" key={row.name}>

          <span>{row.name}</span>

          <div className="heat-bar">

            <div
              className="heat-fill"
              style={{
                width: `${(row.value / max) * 100}%`
              }}
            />

          </div>

          <strong>{row.value}</strong>

        </div>
      ))}

    </section>
  );
}