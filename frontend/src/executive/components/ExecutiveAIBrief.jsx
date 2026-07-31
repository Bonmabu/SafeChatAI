import "./ExecutiveAIBrief.css";

export default function ExecutiveAIBrief({ brief }) {

  if (!brief) return null;

  const risks = brief.top_business_risks || [];
  const actions =
    brief.recommended_actions ||
    brief.strategic_recommendations ||
    [];

  const predictions = brief.predictions || {};

  return (
    <div className="executive-ai-brief">

      <h2>🤖 AI Executive Brief</h2>

      <div className="brief-risk">
        Overall Risk:
        <strong> {brief.overall_risk || brief.risk_level || "Unknown"}</strong>
      </div>

      <p>
        {brief.executive_summary ||
         brief.summary ||
         "No executive summary available."}
      </p>

      <h3>Top Business Risks</h3>

      <ul>
        {risks.length > 0 ? (
          risks.map((item, i) => (
            <li key={i}>{item}</li>
          ))
        ) : (
          <li>No business risks available.</li>
        )}
      </ul>

      <h3>Recommended Actions</h3>

      <ul>
        {actions.length > 0 ? (
          actions.map((item, i) => (
            <li key={i}>{item}</li>
          ))
        ) : (
          <li>No recommendations available.</li>
        )}
      </ul>

      <div className="prediction">
        Next 24h:
        <strong> {predictions.next_24h || "N/A"}</strong>

        <br />

        Confidence:
        <strong> {predictions.confidence ?? "N/A"}%</strong>
      </div>

    </div>
  );
}