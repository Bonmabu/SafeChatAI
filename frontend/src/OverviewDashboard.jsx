import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import "./OverviewDashboard.css";

const API =
  import.meta.env.VITE_API_BASE ||
  "http://127.0.0.1:8000";

const auth = () => ({
  headers: {
    Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
  },
});

export default function OverviewDashboard() {
  const navigate = useNavigate();

  const [summary, setSummary] = useState({});
  const [health, setHealth] = useState({});
  const [incidents, setIncidents] = useState([]);
  const [attackGraph, setAttackGraph] = useState({
    nodes: [],
    edges: [],
    links: [],
  });
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      try {
        const [summaryRes, healthRes, incidentsRes, graphRes] =
          await Promise.allSettled([
            axios.get(`${API}/soc-summary`, auth()),
            axios.get(`${API}/health`, auth()),
            axios.get(`${API}/incidents`, auth()),
            axios.get(`${API}/attack-graph`, auth()),
          ]);

        if (!mounted) return;

        if (summaryRes.status === "fulfilled") {
          setSummary(summaryRes.value.data || {});
        }

        if (healthRes.status === "fulfilled") {
          setHealth(healthRes.value.data || {});
        }

        if (incidentsRes.status === "fulfilled") {
          const data = incidentsRes.value.data;
          setIncidents(
            Array.isArray(data)
              ? data
              : data?.incidents || []
          );
        }

        if (graphRes.status === "fulfilled") {
          const data = graphRes.value.data || {};
          setAttackGraph({
            nodes: data.nodes || [],
            edges: data.edges || data.links || [],
            links: data.links || data.edges || [],
          });
        }

        setLastUpdated(new Date());
      } catch (error) {
        console.error("Overview dashboard error:", error);
      }
    };

    load();

    const timer = setInterval(load, 15000);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const totalScans =
    summary.total_scans ??
    summary.totalScans ??
    0;

  const totalAlerts =
    summary.total_alerts ??
    summary.totalAlerts ??
    0;

  const totalIncidents =
    summary.total_incidents ??
    summary.totalIncidents ??
    0;

  const openIncidents =
    summary.open_incidents ??
    summary.openIncidents ??
    incidents.filter(
      (item) =>
        String(item.status || "").toLowerCase() ===
        "open"
    ).length;

  const attackNodes = Array.isArray(attackGraph.nodes)
    ? attackGraph.nodes.length
    : 0;

  const attackLinks = Array.isArray(attackGraph.edges)
    ? attackGraph.edges.length
    : 0;

  const criticalIncidents = incidents.filter((item) => {
    const risk = Number(
      item.risk ??
        item.score ??
        item.severity ??
        0
    );

    return risk >= 85;
  }).length;

  const systemOnline =
    health.status === "online" ||
    health.status === "operational" ||
    health.status === "healthy";

  const posture =
    criticalIncidents > 0
      ? "ELEVATED"
      : openIncidents > 0
        ? "GUARDED"
        : "HEALTHY";

  const postureClass =
    posture === "ELEVATED"
      ? "overview-danger"
      : posture === "GUARDED"
        ? "overview-warning"
        : "overview-success";

  const latestIncidents = [...incidents]
    .sort((a, b) => {
      const ta = new Date(
        a.created_at ||
          a.timestamp ||
          a.time ||
          0
      ).getTime();

      const tb = new Date(
        b.created_at ||
          b.timestamp ||
          b.time ||
          0
      ).getTime();

      return tb - ta;
    })
    .slice(0, 6);

  return (
    <div className="overview-page">

      <section className="overview-hero">
        <div className="overview-hero-copy">
          <div className="overview-eyebrow">
            <span
              className={`overview-status-dot ${
                systemOnline
                  ? "overview-online"
                  : "overview-offline"
              }`}
            />
            {systemOnline
              ? "SYSTEM ONLINE"
              : "SYSTEM CHECK REQUIRED"}
          </div>

          <h1>🛡️ SafeChat AI SOC Command Center</h1>

          <p>
            Enterprise Security Command Center
          </p>

          <span className="overview-live-badge">
            LIVE AI MONITORING
          </span>
        </div>

        <div className="overview-hero-posture">
          <span>Current Posture</span>
          <strong className={postureClass}>
            {posture}
          </strong>
          <small>
            {lastUpdated
              ? `Updated ${lastUpdated.toLocaleTimeString()}`
              : "Synchronizing..."}
          </small>
        </div>
      </section>

      <section className="overview-kpis">

        <div className="overview-kpi">
          <span>&#x1F4CA; Security Events</span>
          <strong>{totalScans}</strong>
          <small>processed</small>
        </div>

        <div className="overview-kpi">
          <span>&#x26A0;&#xFE0F; Alerts</span>
          <strong>{totalAlerts}</strong>
          <small>detected</small>
        </div>

        <div className="overview-kpi">
          <span>&#x1F6A8; Open Incidents</span>
          <strong>{openIncidents}</strong>
          <small>{criticalIncidents} critical</small>
        </div>

        <div className="overview-kpi">
          <span>&#x1F578;&#xFE0F; Attack Nodes</span>
          <strong>{attackNodes}</strong>
          <small>{attackLinks} connections</small>
        </div>

      </section>

      <section className="overview-grid">

        <div className="overview-panel overview-command">
          <div className="overview-panel-title">
            <div>
              <span className="overview-section-icon">
                &#x1F9E0;
              </span>
              <div>
                <h2>AI Security Pulse</h2>
                <p>What the SOC is seeing now</p>
              </div>
            </div>

            <span className="overview-live-text">
              LIVE
            </span>
          </div>

          <div className="overview-pulse">

            <div>
              <span>Threat Pressure</span>
              <strong>
                {criticalIncidents > 0
                  ? "HIGH"
                  : openIncidents > 0
                    ? "MEDIUM"
                    : "LOW"}
              </strong>
            </div>

            <div>
              <span>Incident State</span>
              <strong>
                {openIncidents > 0
                  ? "ACTIVE"
                  : "STABLE"}
              </strong>
            </div>

            <div>
              <span>Attack Surface</span>
              <strong>
                {attackNodes > 0
                  ? "MONITORED"
                  : "INITIALIZING"}
              </strong>
            </div>

          </div>

          <div className="overview-brief">
            <strong>AI Security Brief</strong>
            <p>
              {criticalIncidents > 0
                ? "Critical activity requires immediate investigation and containment."
                : openIncidents > 0
                  ? "Open incidents are being monitored. Review active response queues."
                  : "Enterprise security posture is stable. Continue proactive monitoring."}
            </p>
          </div>

          <div className="overview-actions">
            <button
              onClick={() =>
                navigate("/dashboard/customer")
              }
            >
              Open Customer SOC
            </button>

            <button
              onClick={() =>
                navigate("/dashboard/executive")
              }
            >
              Open Executive War Room
            </button>

            <button
              onClick={() =>
                navigate("/dashboard/admin")
              }
            >
              Open Admin SOC
            </button>
          </div>
        </div>

        <div className="overview-panel">
          <div className="overview-panel-title">
            <div>
              <span className="overview-section-icon">
                &#x1F4E1;
              </span>
              <div>
                <h2>Live Threat Stream</h2>
                <p>Latest SOC activity</p>
              </div>
            </div>
          </div>

          <div className="overview-feed">
            {latestIncidents.length === 0 ? (
              <div className="overview-empty">
                No incident activity currently available.
              </div>
            ) : (
              latestIncidents.map((item, index) => {
                const risk = Number(
                  item.risk ??
                    item.score ??
                    item.severity ??
                    0
                );

                return (
                  <div
                    className="overview-feed-item"
                    key={
                      item.id ??
                      `${item.category}-${index}`
                    }
                  >
                    <span
                      className={
                        risk >= 85
                          ? "feed-dot danger"
                          : risk >= 50
                            ? "feed-dot warning"
                            : "feed-dot normal"
                      }
                    />

                    <div>
                      <strong>
                        {item.category ||
                          item.type ||
                          "Security Event"}
                      </strong>

                      <small>
                        Risk {risk}
                        {item.status
                          ? ` • ${item.status}`
                          : ""}
                      </small>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

      </section>

      <section className="overview-panel overview-navigation-panel">
        <div className="overview-panel-title">
          <div>
            <span className="overview-section-icon">
              &#x1F5FA;&#xFE0F;
            </span>

            <div>
              <h2>Security Operations</h2>
              <p>Unified access to the complete SafeChat intelligence workspace</p>
            </div>
          </div>

          <span className="overview-live-text">
            COMMAND CENTER
          </span>
        </div>

        <div className="overview-modules">

          <button
            onClick={() =>
              navigate("/dashboard/customer")
            }
          >
            <span>&#x1F6E1;&#xFE0F;</span>
            <strong>Customer SOC</strong>
            <small>Threat operations, incidents & analytics</small>
          </button>

          <button
            onClick={() =>
              navigate("/dashboard/campaigns")
            }
          >
            <span>&#x1F3AF;</span>
            <strong>Campaign Investigation</strong>
            <small>Investigate coordinated threat activity</small>
          </button>

          <button
            onClick={() =>
              navigate("/dashboard/reports")
            }
          >
            <span>&#x1F4CA;</span>
            <strong>Reports & Intelligence</strong>
            <small>AI investigations, reports & intelligence</small>
          </button>

          <button
            onClick={() =>
              navigate("/dashboard/executive")
            }
          >
            <span>&#x1F9E0;</span>
            <strong>Executive / IT</strong>
            <small>Risk, posture & strategic security insight</small>
          </button>

          <button
            onClick={() =>
              navigate("/dashboard/admin")
            }
          >
            <span>&#x2699;&#xFE0F;</span>
            <strong>Admin SOC</strong>
            <small>Users, governance & platform administration</small>
          </button>

          <button
            onClick={() =>
              navigate("/dashboard/customer/timeline")
            }
          >
            <span>&#x1F552;</span>
            <strong>Security Timeline</strong>
            <small>Trace incidents and activity over time</small>
          </button>

          <button
            onClick={() =>
              navigate("/dashboard/customer/analytics")
            }
          >
            <span>&#x1F4C8;</span>
            <strong>Security Analytics</strong>
            <small>Deep threat trends and operational analytics</small>
          </button>

        </div>
      </section>

      <footer className="overview-footer">
        <span>
          SafeChat AI Security Operations Center
        </span>

        <span>
          {systemOnline
            ? "Protected session • AI monitoring active"
            : "System health requires attention"}
        </span>
      </footer>

    </div>
  );
}
