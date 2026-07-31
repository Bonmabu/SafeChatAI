function Card({ title, value }) {
  return (
    <div
      style={{
        background: "linear-gradient(135deg,#1e293b,#0f172a)",
        padding: "20px",
        borderRadius: "14px",
        border: "1px solid #334155",
        boxShadow: "0 0 20px rgba(0,255,255,0.15)",
        color: "#ffffff"
      }}
    >
      <h4
        style={{
          color: "#94a3b8",
          fontSize: "14px",
          textTransform: "uppercase",
          letterSpacing: "1px",
          margin: 0
        }}
      >
        {title}
      </h4>

      <h2
        style={{
          color: title === "Critical" ? "#ef4444" : "#38bdf8",
          fontSize: "32px",
          fontWeight: "700",
          marginTop: "10px"
        }}
      >
        {value}
      </h2>
    </div>
  );
}


export default function KPICards({ summary }) {

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(6,1fr)",
        gap: 10,
        marginBottom: 20
      }}
    >

      <Card 
        title="Scans" 
        value={summary?.total_scans ?? 0}
      />

      <Card 
        title="Alerts" 
        value={summary?.total_alerts ?? 0}
      />

      <Card 
        title="Incidents" 
        value={summary?.total_incidents ?? 0}
      />

      <Card 
        title="Open" 
        value={summary?.open_incidents ?? 0}
      />

      <Card 
        title="Status" 
        value={summary?.status ?? "LOADING"}
      />

      <Card 
        title="Critical" 
        value={summary?.critical_threats ?? 0}
      />

    </div>
  );
}