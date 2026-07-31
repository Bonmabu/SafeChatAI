import { useEffect, useState } from "react";
import axios from "axios";
import CustomerNav from "./CustomerNav";

const API =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function CustomerTimeline() {
  const tenantId = "demo";
  const [events, setEvents] = useState([]);

  useEffect(() => {
    loadTimeline();
    const interval = setInterval(loadTimeline, 5000);
    return () => clearInterval(interval);
  }, []);

  async function loadTimeline() {
    try {
      const [alertsRes, incidentsRes] = await Promise.all([
        axios.get(`${API}/customer/alerts`, {
          params: { tenant_id: tenantId }
        }),
        axios.get(`${API}/customer/incidents`, {
          params: { tenant_id: tenantId }
        })
      ]);

      const alertEvents = alertsRes.data.map(a => ({
        id: `alert-${a.id}`,
        icon: "🚨",
        title: a.level,
        message: a.message,
        time: a.created_at
      }));

      const incidentEvents = incidentsRes.data.map(i => ({
        id: `incident-${i.id}`,
        icon: i.status === "RESOLVED" ? "🟢" : "🔴",
        title: `${i.category} (${i.status})`,
        message: i.message,
        time: i.created_at
      }));

      const merged = [...alertEvents, ...incidentEvents].sort(
        (a, b) => new Date(b.time) - new Date(a.time)
      );

      setEvents(merged);
    } catch (err) {
      console.error(err);
    }
  }

  return (
    <div
      style={{
        background: "#111827",
        color: "white",
        padding: 20,
        borderRadius: 10
      }}
    >
      <h2>📜 Threat Timeline</h2>
<h1>📜 Customer Threat Timeline</h1>
<CustomerNav />

      {events.length === 0 ? (
        <p>No activity.</p>
      ) : (
        events.map(event => (
          <div
            key={event.id}
            style={{
              borderBottom: "1px solid #374151",
              padding: "12px 0"
            }}
          >
            <div style={{ fontWeight: "bold" }}>
              {event.icon} {event.title}
            </div>

            <div>{event.message}</div>

            <small style={{ color: "#9ca3af" }}>
              {event.time}
            </small>
          </div>
        ))
      )}
    </div>
  );
}