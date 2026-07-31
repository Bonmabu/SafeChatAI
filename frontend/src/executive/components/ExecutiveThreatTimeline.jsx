import React from "react";
import "./ExecutiveThreatTimeline.css";

export default function ExecutiveThreatTimeline({
  incidents = []
}) {

  const latest = [...incidents]
  .sort((a, b) => (Number(b.id) || 0) - (Number(a.id) || 0))
  .slice(0, 8);

  return (

    <section className="timeline-panel">

      <div className="timeline-header">

        <h2>⏱ Executive Threat Timeline</h2>

        <div className="timeline-live">
          LIVE
        </div>

      </div>

      {latest.length===0 && (

        <div className="timeline-empty">
          Waiting for security events...
        </div>

      )}

      {latest.map((item,index)=>(

        <div
          className="timeline-row"
          key={index}
        >

          <div className="timeline-dot"/>

          <div className="timeline-line"/>

          <div className="timeline-card">

            <div className="timeline-top">

              <strong>
  {item.category || "Unknown Threat"}
</strong>

<span>
  Risk {item.score ?? item.risk_score ?? 0}
</span>

            </div>

            <div className="timeline-bottom">

              {item.message || item.text || item.category}

            </div>

          </div>

        </div>

      ))}

    </section>

  );

}