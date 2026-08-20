import { useEffect, useState } from "react";
import axios from "axios";
import CustomerNav from "./CustomerNav";

const getTenantId = () => {
  const token = localStorage.getItem("token");

  if (!token) return null;

  try {
    return JSON.parse(atob(token.split(".")[1])).tenant_id;
  } catch {
    return null;
  }
};

const API = import.meta.env.VITE_API_BASE;

export default function CustomerTimeline() {
  const tenantId = getTenantId();
  const [events, setEvents] = useState([]);

  useEffect(() => {
    loadTimeline();
    const interval = setInterval(loadTimeline, 5000);
    return () => clearInterval(interval);
  }, []);

  async function loadTimeline() {
    try {
      const token = localStorage.getItem("token");

      const authConfig = {
        headers: {
          Authorization: `Bearer ${token}`
        },
        params: {
          tenant_id: tenantId
        }
      };

      const [alertsRes, incidentsRes] = await Promise.all([
        axios.get(`${API}/customer/alerts`, authConfig),
        axios.get(`${API}/customer/incidents`, authConfig)
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