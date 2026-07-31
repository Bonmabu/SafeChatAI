import { CountUp } from "react-countup";

export default function KPICards({ kpis }) {
  if (!kpis) return null;

  const Card = ({ title, value }) => (
    <div
      style={{
        background: "#111827",
        border: "1px solid #334155",
        borderRadius: 16,
        padding: 24,
        textAlign: "center"
      }}
    >
      <div
        style={{
          color: "#94a3b8",
          marginBottom: 10
        }}
      >
        {title}
      </div>

      <div
        style={{
          fontSize: 32,
          color: "#00ffc8",
          fontWeight: "bold"
        }}
      >
        {Number(value) || 0}
      </div>
    </div>
  );

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
        gap: 20
      }}
    >
      <Card title="Security Score" value={kpis.security_score} />
      <Card title="Enterprise Risk" value={kpis.enterprise_risk} />
      <Card title="Total Scans" value={kpis.total_scans} />
      <Card title="Alerts" value={kpis.total_alerts} />
      <Card title="Incidents" value={kpis.total_incidents} />
      <Card title="Open Incidents" value={kpis.open_incidents} />
    </div>
  );
}