import React from "react";
import "./MitreAttackMatrix.css";

export default function MitreAttackMatrix({
  matrix = {}
}) {

  const stages = Object.entries(matrix);

  const color = (value) => {

    if (value >= 80) return "#ef4444";
    if (value >= 60) return "#f97316";
    if (value >= 40) return "#facc15";

    return "#22c55e";
  };

  return (

    <section className="mitre-container">

      <h2>🛡 MITRE ATT&CK Matrix</h2>

      <p>
        Live MITRE ATT&CK tactic distribution across the enterprise
      </p>

      <div className="mitre-grid">

{stages.map(([stage,value]) => (

  <div
    key={stage}
    className="mitre-card"
    style={{
      borderLeft:`6px solid ${color(value)}`
    }}
  >

    <h3>
      {stage}
    </h3>


    <h1
      style={{
        color:color(value)
      }}
    >
      {value}
    </h1>


    <small>
      {value}% of attack chain
    </small>


    <div
      style={{
        height:8,
        background:"#1e293b",
        borderRadius:20,
        overflow:"hidden",
        marginTop:12
      }}
    >

      <div
        style={{
          width:`${value}%`,
          height:"100%",
          background:color(value),
          transition:"0.5s"
        }}
      />

    </div>


  </div>

))}

      </div>

    </section>

  );

}