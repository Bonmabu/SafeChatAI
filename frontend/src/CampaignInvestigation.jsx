import { useEffect, useMemo, useState } from "react";
import "./CampaignInvestigation.css";

import axios from "axios";
const API_BASE =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

function authHeaders() {
  const token = localStorage.getItem("token");

  return token
    ? {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      }
    : {
        "Content-Type": "application/json",
      };
}

function riskClass(score) {
  if (score >= 70) return "critical";
  if (score >= 50) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export default function CampaignInvestigation() {
  const [campaigns, setCampaigns] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [forensicInvestigation, setForensicInvestigation] = useState(null);
const [evidenceGraph, setEvidenceGraph] = useState(null);
const [evidenceGraphLoading, setEvidenceGraphLoading] = useState(false);
    
  useEffect(() => {
    let active = true;

    const loadEvidenceGraph = async () => {
      if (!selectedId) {
        if (active) setEvidenceGraph(null);
        return;
      }

      setEvidenceGraphLoading(true);

      try {
        const response = await axios.get(
          `${API_BASE}/forensics/evidence-graph?incident_id=${encodeURIComponent(selectedId)}`,
          { headers: authHeaders() }
        );

        if (active) {
          setEvidenceGraph(response.data);
        }
      } catch (err) {
        console.warn("[EVIDENCE GRAPH] Unavailable:", err);
        if (active) setEvidenceGraph(null);
      } finally {
        if (active) setEvidenceGraphLoading(false);
      }
    };

    loadEvidenceGraph();

    return () => {
      active = false;
    };
  }, [selectedId]);

  const [forensicLoading, setForensicLoading] = useState(false);
const [threatReplay, setThreatReplay] = useState(null);
const [replayIndex, setReplayIndex] = useState(0);
const [replayStepData, setReplayStepData] = useState(null);

  const [selectedEvent, setSelectedEvent] = useState(null);
  const [eventLoading, setEventLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");

  async function loadCampaigns(showLoading = false) {
    try {
      if (showLoading) {
        setLoading(true);
      }

      setError("");

      const response = await fetch(
        `${API_BASE}/attack-campaigns?limit=50`,
        {
          headers: authHeaders(),
        }
      );

      if (!response.ok) {
        throw new Error(`Campaign request failed: ${response.status}`);
      }

      const data = await response.json();

      const items = Array.isArray(data.campaigns)
        ? data.campaigns
        : [];

      setCampaigns(items);

      setSelectedId((current) => {
        if (current && items.some((item) => item.campaign_id === current)) {
          return current;
        }

        return items.length > 0 ? items[0].campaign_id : "";
      });
    } catch (err) {
      setError(err.message || "Unable to load campaigns");
    } finally {
      if (showLoading) {
        setLoading(false);
      }
    }
  }

  const loadReplayStep = async (index) => {
  try {
    const response = await axios.get(
      `${API_BASE}/attack-replay/step?index=${index}`,
      { headers: authHeaders() }
    );

    setReplayStepData(response.data);
    setReplayIndex(response.data?.index ?? index);
  } catch (err) {
    console.warn("[REPLAY] Step unavailable:", err);
  }
};

useEffect(() => {
  let active = true;

  const loadThreatReplay = async () => {
    try {
      const response = await axios.get(
        `${API_BASE}/attack-replay`,
        { headers: authHeaders() }
      );

      if (active) {
        setThreatReplay(response.data);
        if ((response.data?.count ?? 0) > 0) {
          loadReplayStep(0);
        }
      }
    } catch (err) {
      if (active) {
        setThreatReplay(null);
      }
    }
  };

  loadThreatReplay();

  return () => {
    active = false;
  };
}, []);

useEffect(() => {
    let active = true;

    async function initialLoad() {
      if (!active) return;
      await loadCampaigns(true);
    }

    initialLoad();

    return () => {
      active = false;
    };
  }, []);

  async function loadCampaignDetail(campaignId, showLoading = false) {
    if (!campaignId) {
      setSelectedCampaign(null);
      return;
    }

    try {
      if (showLoading) {
        setDetailLoading(true);
      }

      const response = await fetch(
        `${API_BASE}/attack-campaigns/${campaignId}`,
        {
          headers: authHeaders(),
        }
      );

      if (!response.ok) {
        throw new Error(`Campaign detail failed: ${response.status}`);
      }

      const data = await response.json();

      setSelectedCampaign(data.campaign || null);
    } catch (err) {
      setError(err.message || "Unable to load campaign");
      setSelectedCampaign(null);
    } finally {
      if (showLoading) {
        setDetailLoading(false);
      }
    }
  }

  useEffect(() => {
    loadCampaignDetail(selectedId, true);
  }, [selectedId]);


  useEffect(() => {
    if (!selectedId) {
      setInvestigation(null);
      return;
    }

    let active = true;

    async function loadInvestigation() {
      try {
        const response = await fetch(
          `${API_BASE}/attack-campaigns/${selectedId}/investigation`,
          {
            headers: authHeaders(),
          }
        );

        if (!response.ok) {
          throw new Error(
            `Investigation request failed: ${response.status}`
          );
        }

        const data = await response.json();

        if (active) {
          setInvestigation(
            data.investigation || null
          );
        }
      } catch (err) {
        console.warn(
          "[CAMPAIGN] Investigation unavailable:",
          err
        );

        if (active) {
          setInvestigation(null);
        }
      }
    }

    loadInvestigation();

    return () => {
      active = false;
    };
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) {
      setForensicInvestigation(null);
      return;
    }

    let active = true;

    async function loadForensicInvestigation() {
      setForensicLoading(true);

      try {
        const response = await fetch(
          `${API_BASE}/forensics/investigation/${selectedId}`,
          {
            headers: authHeaders(),
          }
        );

        if (!response.ok) {
          throw new Error(
            `Forensic investigation request failed: ${response.status}`
          );
        }

        const data = await response.json();

        if (active) {
          setForensicInvestigation(data);
        }
      } catch (err) {
        console.warn(
          "[FORENSICS] Investigation unavailable:",
          err
        );

        if (active) {
          setForensicInvestigation(null);
        }
      } finally {
        if (active) {
          setForensicLoading(false);
        }
      }
    }

    loadForensicInvestigation();

    return () => {
      active = false;
    };
  }, [selectedId]);



  useEffect(() => {
    const configuredWs =
      import.meta.env.VITE_WS_URL ||
      import.meta.env.VITE_WS_BASE ||
      "ws://127.0.0.1:8000/ws/soc";

    let ws;
    let reconnectTimer;
    let closed = false;

    const refreshTypes = new Set([
      "security_event",
      "scan_event",
      "alert_event",
      "incident_event",
      "attack_graph",
      "threat_dna",
      "digital_twin",
      "digital_twin_update",
      "campaign_update",
      "soc_summary",
      "soc_update",
    ]);

    const connect = () => {
      if (closed) return;

      try {
        ws = new WebSocket(configuredWs);

        ws.onopen = () => {
          console.log("[CAMPAIGN] WebSocket connected");
        };

        ws.onmessage = async (messageEvent) => {
          try {
            const payload = JSON.parse(messageEvent.data);

            const eventType =
              payload?.type ||
              payload?.event_type ||
              payload?.data?.type ||
              payload?.data?.event_type;

            if (refreshTypes.has(eventType)) {
              await loadCampaigns(false);

              if (selectedId) {
                await loadCampaignDetail(
                  selectedId,
                  false
                );

                try {
                  const investigationResponse = await fetch(
                    `${API_BASE}/attack-campaigns/${selectedId}/investigation`,
                    {
                      headers: authHeaders(),
                    }
                  );

                  if (investigationResponse.ok) {
                    const investigationData =
                      await investigationResponse.json();

                    setInvestigation(
                      investigationData.investigation || null
                    );
                  }
                } catch (investigationError) {
                  console.warn(
                    "[CAMPAIGN] Live investigation refresh failed:",
                    investigationError
                  );
                }
              }
            }
          } catch (err) {
            console.warn(
              "[CAMPAIGN] WebSocket message ignored:",
              err
            );
          }
        };

        ws.onerror = () => {
          ws?.close();
        };

        ws.onclose = () => {
          if (closed) return;

          console.log(
            "[CAMPAIGN] WebSocket disconnected; reconnecting"
          );

          reconnectTimer = setTimeout(
            connect,
            3000
          );
        };
      } catch (err) {
        console.warn(
          "[CAMPAIGN] WebSocket connection failed:",
          err
        );

        reconnectTimer = setTimeout(
          connect,
          3000
        );
      }
    };

    connect();

    return () => {
      closed = true;

      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }

      if (ws) {
        ws.close();
      }
    };
  }, [selectedId]);


  async function openSecurityEvent(eventId) {
    if (!eventId) return;

    try {
      setEventLoading(true);
      setSelectedEvent(null);

      const response = await fetch(
        `${API_BASE}/security-events/event/${encodeURIComponent(eventId)}`,
        {
          headers: authHeaders(),
        }
      );

      if (!response.ok) {
        throw new Error(
          `Security event request failed: ${response.status}`
        );
      }

      const data = await response.json();

      setSelectedEvent(data.event || null);
    } catch (err) {
      console.warn(
        "[CAMPAIGN] Event evidence unavailable:",
        err
      );

      setSelectedEvent({
        event_id: eventId,
        error: err.message || "Unable to load event",
      });
    } finally {
      setEventLoading(false);
    }
  }

  const selectedRisk = Number(
    selectedCampaign?.risk_score || 0
  );

  const selectedEdges = selectedCampaign?.edges || [];

  const eventEdges = useMemo(
    () =>
      selectedEdges.filter(
        (edge) => edge.relationship === "CONTAINS_EVENT"
      ),
    [selectedEdges]
  );

  const mitreEdges = useMemo(
    () =>
      selectedEdges.filter(
        (edge) => edge.relationship === "USES_MITRE_TECHNIQUE"
      ),
    [selectedEdges]
  );

  return (
    <div className="campaign-page">
      <div className="campaign-hero">
        <div>
          <div className="campaign-eyebrow">
            SECURITY INTELLIGENCE
          </div>

          <h1>Campaign Investigation Center</h1>

          <p>
            Follow correlated security activity from first detection
            to campaign-level intelligence.
          </p>
        </div>

        <div className="campaign-live-badge">
          <span className="campaign-live-dot" />
          LIVE INTELLIGENCE
        </div>
      </div>

      {error && (
        <div className="campaign-error">
          {error}
        </div>
      )}

      <div className="campaign-layout">
        <aside className="campaign-sidebar">
          <div className="campaign-sidebar-header">
            <span>Active campaigns</span>
            <strong>{campaigns.length}</strong>
          </div>

          {loading ? (
            <div className="campaign-empty">
              Loading campaigns...
            </div>
          ) : campaigns.length === 0 ? (
            <div className="campaign-empty">
              No campaign clusters detected yet.
            </div>
          ) : (
            <div className="campaign-list">
              {campaigns.map((campaign) => {
                const score = Number(campaign.risk_score || 0);
                const level = riskClass(score);

                return (
                  <button
                    key={campaign.campaign_id}
                    type="button"
                    className={`campaign-list-item ${
                      selectedId === campaign.campaign_id
                        ? "selected"
                        : ""
                    }`}
                    onClick={() =>
                      setSelectedId(campaign.campaign_id)
                    }
                  >
                    <div className="campaign-list-top">
                      <span
                        className={`campaign-score-dot ${level}`}
                      />
                      <span className="campaign-list-name">
                        {campaign.name || "Security Campaign"}
                      </span>
                    </div>

                    <div className="campaign-list-meta">
                      <span>
                        {campaign.event_count || 0} events
                      </span>
                      <span>
                        Risk {score.toFixed(1)}
                      </span>
                    </div>

                    <div className="campaign-list-id">
                      {campaign.campaign_id}
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </aside>

        <main className="campaign-main">
          {detailLoading ? (
            <div className="campaign-loading">
              Loading campaign intelligence...
            </div>
          ) : !selectedCampaign ? (
            <div className="campaign-loading">
              Select a campaign to investigate.
            </div>
          ) : (
            <>
              <section className="campaign-summary">
                <div>
                  <div className="campaign-summary-label">
                    ACTIVE CAMPAIGN
                  </div>

                  <h2>
                    {selectedCampaign.name ||
                      "Security Campaign"}
                  </h2>

                  <p className="campaign-campaign-id">
                    {selectedCampaign.campaign_id}
                  </p>
                </div>

                <div
                  className={`campaign-risk-badge ${riskClass(
                    selectedRisk
                  )}`}
                >
                  <span>RISK</span>
                  <strong>{selectedRisk.toFixed(1)}</strong>
                </div>
              </section>

              <section className="campaign-kpis">
                <div className="campaign-kpi">
                  <span>Severity</span>
                  <strong>
                    {selectedCampaign.severity || "LOW"}
                  </strong>
                </div>

                <div className="campaign-kpi">
                  <span>Confidence</span>
                  <strong>
                    {Number(
                      selectedCampaign.confidence || 0
                    ).toFixed(1)}
                    %
                  </strong>
                </div>

                <div className="campaign-kpi">
                  <span>Events</span>
                  <strong>
                    {selectedCampaign.event_count || 0}
                  </strong>
                </div>

                <div className="campaign-kpi">
                  <span>Priority</span>
                  <strong>
                    {selectedCampaign.investigation_priority ||
                      "LOW"}
                  </strong>
                </div>
              </section>

              <section className="campaign-grid">
                <div className="campaign-card campaign-card-wide">
                  <div className="campaign-card-title">
                    Campaign Overview
                  </div>

                  <div className="campaign-overview-grid">
                    <div>
                      <span>Category</span>
                      <strong>
                        {selectedCampaign.primary_category ||
                          "Unknown"}
                      </strong>
                    </div>

                    <div>
                      <span>Status</span>
                      <strong>
                        {selectedCampaign.status || "ACTIVE"}
                      </strong>
                    </div>

                    <div>
                      <span>First seen</span>
                      <strong>
                        {selectedCampaign.first_seen || "—"}
                      </strong>
                    </div>

                    <div>
                      <span>Last seen</span>
                      <strong>
                        {selectedCampaign.last_seen || "—"}
                      </strong>
                    </div>
                  </div>
                </div>

                <div className="campaign-card">
                  <div className="campaign-card-title">
                    Affected Users
                  </div>

                  <div className="campaign-tags">
                    {(selectedCampaign.affected_users || []).map(
                      (item) => (
                        <span key={item}>{item}</span>
                      )
                    )}

                    {!(selectedCampaign.affected_users || [])
                      .length && <em>None detected</em>}
                  </div>
                </div>

                <div className="campaign-card">
                  <div className="campaign-card-title">
                    Devices
                  </div>

                  <div className="campaign-tags">
                    {(selectedCampaign.affected_devices || []).map(
                      (item) => (
                        <span key={item}>{item}</span>
                      )
                    )}

                    {!(selectedCampaign.affected_devices || [])
                      .length && <em>None detected</em>}
                  </div>
                </div>

                <div className="campaign-card">
                  <div className="campaign-card-title">
                    Network Indicators
                  </div>

                  <div className="campaign-tags">
                    {(selectedCampaign.affected_ips || []).map(
                      (item) => (
                        <span key={item}>{item}</span>
                      )
                    )}

                    {!(selectedCampaign.affected_ips || [])
                      .length && <em>None detected</em>}
                  </div>
                </div>

                <div className="campaign-card">
                  <div className="campaign-card-title">
                    MITRE Techniques
                  </div>

                  <div className="campaign-tags">
                    {(selectedCampaign.mitre_techniques || []).map(
                      (item) => (
                        <span key={item}>{item}</span>
                      )
                    )}

                    {!(selectedCampaign.mitre_techniques || [])
                      .length && <em>No mapped techniques</em>}
                  </div>
                </div>

                <div className="campaign-card campaign-card-wide">
                  <div className="campaign-card-title">
                    Investigation Recommendation
                  </div>

                  <div className="campaign-recommendation">
                    <div className="campaign-recommendation-icon">
                      !
                    </div>

                    <div>
                      <strong>
                        {selectedCampaign.investigation_priority ||
                          "MONITOR"}
                      </strong>

                      <p>
                        {selectedCampaign.recommendation ||
                          "Continue monitoring for related activity."}
                      </p>
                    </div>
                  </div>
                </div>
              </section>

              <section className="campaign-card campaign-card-wide">
                <div className="campaign-card-header-row">
                  <div className="campaign-card-title">
                    Campaign Timeline
                  </div>

                  <span>
                    {investigation?.timeline?.event_count || 0} events
                  </span>
                </div>

                <div className="campaign-timeline">
                  {(investigation?.timeline?.events || []).map(
                    (event, index) => (
                      <div
                        className="campaign-timeline-item"
                        key={`${event.event_id}-${index}`}
                      >
                        <div className="campaign-timeline-marker">
                          <span />
                        </div>

                        <button
                          type="button"
                          className="campaign-timeline-content campaign-timeline-button"
                          onClick={() =>
                            openSecurityEvent(event.event_id)
                          }
                        >
                          <div className="campaign-timeline-top">
                            <strong>
                              {event.phase}
                            </strong>

                            <span>
                              {event.timestamp || "Unknown time"}
                            </span>
                          </div>

                          <div className="campaign-timeline-event">
                            {event.event_type}
                          </div>

                          <div className="campaign-timeline-meta">
                            <span>
                              {event.category || "Unknown"}
                            </span>

                            <span>
                              Risk {Number(
                                event.risk_score || 0
                              ).toFixed(1)}
                            </span>

                            {event.user && (
                              <span>
                                User: {event.user}
                              </span>
                            )}

                            {event.device && (
                              <span>
                                Device: {event.device}
                              </span>
                            )}

                            {event.ip && (
                              <span>
                                IP: {event.ip}
                              </span>
                            )}
                          </div>
                        </button>
                      </div>
                    )
                  )}

                  {!(investigation?.timeline?.events || []).length && (
                    <div className="campaign-loading">
                      No correlated timeline events available.
                    </div>
                  )}
                </div>
              </section>

              <section className="campaign-card campaign-card-wide">
                <div className="campaign-card-header-row">
                  <div className="campaign-card-title">
                    Response Orchestration
                  </div>

                  <span
                    style={{
                      padding: "5px 10px",
                      borderRadius: 999,
                      fontSize: 11,
                      fontWeight: 800,
                      letterSpacing: "0.05em",
                      background:
                        investigation?.response?.status ===
                        "EXECUTED"
                          ? "rgba(34,197,94,0.14)"
                          : investigation?.response?.status ===
                            "BACKFILLED"
                          ? "rgba(245,158,11,0.14)"
                          : "rgba(148,163,184,0.12)",
                      color:
                        investigation?.response?.status ===
                        "EXECUTED"
                          ? "#86efac"
                          : investigation?.response?.status ===
                            "BACKFILLED"
                          ? "#fbbf24"
                          : "#94a3b8",
                    }}
                  >
                    {investigation?.response?.status ||
                      "NO RESPONSE RECORDED"}
                  </span>
                </div>

                <div
                  style={{
                    display: "grid",
                    gap: 12,
                    marginTop: 14,
                  }}
                >
                  {(investigation?.response?.events || []).map(
                    (responseEvent) => {
                      let evidence = {};

                      try {
                        evidence =
                          typeof responseEvent.evidence === "string"
                            ? JSON.parse(responseEvent.evidence)
                            : responseEvent.evidence || {};
                      } catch {
                        evidence = {};
                      }

                      const actions = Array.isArray(
                        evidence.actions
                      )
                        ? evidence.actions
                        : [];

                      return (
                        <div
                          key={responseEvent.event_id}
                          style={{
                            padding: 16,
                            borderRadius: 12,
                            border:
                              "1px solid rgba(51,65,85,0.9)",
                            background: "#0b1220",
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                              gap: 12,
                              flexWrap: "wrap",
                            }}
                          >
                            <div>
                              <div
                                style={{
                                  fontSize: 11,
                                  color: "#64748b",
                                  fontWeight: 800,
                                  letterSpacing: "0.08em",
                                }}
                              >
                                RESPONSE EVENT
                              </div>

                              <strong
                                style={{
                                  display: "block",
                                  marginTop: 5,
                                  color: "#e2e8f0",
                                }}
                              >
                                {responseEvent.source ||
                                  "response_orchestrator"}
                              </strong>
                            </div>

                            <span
                              style={{
                                padding: "5px 9px",
                                borderRadius: 8,
                                fontSize: 11,
                                fontWeight: 800,
                                background:
                                  responseEvent.status ===
                                  "EXECUTED"
                                    ? "rgba(34,197,94,0.12)"
                                    : "rgba(245,158,11,0.12)",
                                color:
                                  responseEvent.status ===
                                  "EXECUTED"
                                    ? "#86efac"
                                    : "#fbbf24",
                              }}
                            >
                              {responseEvent.status ||
                                "UNKNOWN"}
                            </span>
                          </div>

                          <div
                            style={{
                              display: "grid",
                              gridTemplateColumns:
                                "repeat(auto-fit,minmax(140px,1fr))",
                              gap: 10,
                              marginTop: 14,
                            }}
                          >
                            <div>
                              <div
                                style={{
                                  fontSize: 10,
                                  color: "#64748b",
                                  fontWeight: 700,
                                }}
                              >
                                RISK
                              </div>
                              <strong>
                                {Number(
                                  responseEvent.risk_score || 0
                                ).toFixed(1)}
                              </strong>
                            </div>

                            <div>
                              <div
                                style={{
                                  fontSize: 10,
                                  color: "#64748b",
                                  fontWeight: 700,
                                }}
                              >
                                INCIDENT
                              </div>
                              <strong>
                                {evidence.incident_id ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div>
                              <div
                                style={{
                                  fontSize: 10,
                                  color: "#64748b",
                                  fontWeight: 700,
                                }}
                              >
                                CORRELATION
                              </div>
                              <strong
                                style={{
                                  fontSize: 11,
                                  wordBreak: "break-all",
                                }}
                              >
                                {responseEvent.correlation_id ||
                                  "N/A"}
                              </strong>
                            </div>
                          </div>

                          <div
                            style={{
                              marginTop: 14,
                              fontSize: 10,
                              color: "#64748b",
                              fontWeight: 800,
                              letterSpacing: "0.08em",
                            }}
                          >
                            ACTIONS
                          </div>

                          <div
                            style={{
                              display: "flex",
                              gap: 8,
                              flexWrap: "wrap",
                              marginTop: 8,
                            }}
                          >
                            {actions.length ? (
                              actions.map((action, actionIndex) => (
                                <span
                                  key={`${responseEvent.event_id}-${actionIndex}`}
                                  style={{
                                    padding: "7px 10px",
                                    borderRadius: 8,
                                    background:
                                      "rgba(34,197,94,0.10)",
                                    border:
                                      "1px solid rgba(34,197,94,0.25)",
                                    color: "#86efac",
                                    fontSize: 11,
                                    fontWeight: 800,
                                  }}
                                >
                                  ? {action}
                                </span>
                              ))
                            ) : (
                              <span
                                style={{
                                  color: "#94a3b8",
                                  fontSize: 12,
                                }}
                              >
                                No action details recorded.
                              </span>
                            )}
                          </div>

                          <div
                            style={{
                              marginTop: 12,
                              fontSize: 10,
                              color: "#64748b",
                            }}
                          >
                            {responseEvent.timestamp ||
                              "Unknown timestamp"}
                          </div>
                        </div>
                      );
                    }
                  )}

                  {!(investigation?.response?.events || [])
                    .length && (
                    <div
                      style={{
                        padding: 18,
                        borderRadius: 12,
                        border:
                          "1px dashed rgba(71,85,105,0.8)",
                        color: "#94a3b8",
                        textAlign: "center",
                      }}
                    >
                      No response actions have been recorded for
                      this campaign.
                    </div>
                  )}
                </div>
              </section>

              <section className="campaign-card campaign-card-wide">
                <div className="campaign-card-title">
                  Intelligence Evidence
                </div>

                <div className="campaign-evidence-grid">

                  <div className="campaign-evidence-card">
                    <div
                      className="campaign-evidence-label"
                    >
                      THREAT DNA
                    </div>

                    <strong>
                      {investigation?.threat_dna?.status === "ready"
                        ? "READY"
                        : "NOT AVAILABLE"}
                    </strong>

                    {investigation?.threat_dna && (
                      <>
                        <span>
                          {investigation.threat_dna.categories?.join(", ") ||
                            "No categories"}
                        </span>

                        <small>
                          Frequency:{" "}
                          {investigation.threat_dna.frequency ?? 0} ·
                          Recurrence:{" "}
                          {investigation.threat_dna.recurrence ?? 0}
                        </small>

                        <small>
                          MITRE:{" "}
                          {investigation.threat_dna.mitre_techniques?.join(
                            ", "
                          ) || "None"}
                        </small>

                        <small>
                          IOCs:{" "}
                          {Object.values(
                            investigation.threat_dna.ioc_profile || {}
                          ).reduce(
                            (total, values) =>
                              total +
                              (Array.isArray(values) ? values.length : 0),
                            0
                          )}
                        </small>
                      </>
                    )}
                  </div>

<div className="campaign-evidence-card">
                    <div className="campaign-evidence-label">
                      ATTACK GRAPH
                    </div>

                    <strong>
                      {investigation?.attack_graph?.edges?.length ??
                        investigation?.attack_graph?.links?.length ??
                        0}
                    </strong>

                    <span>graph relationships</span>

                    <small>
                      {investigation?.attack_graph?.nodes?.length ??
                        Object.keys(
                          investigation?.attack_graph?.nodes || {}
                        ).length ??
                        0}{" "}
                      nodes
                    </small>
                  </div>

                  <div className="campaign-evidence-card">
                    <div className="campaign-evidence-label">
                      DIGITAL TWIN
                    </div>

                    <strong>
                      {investigation?.digital_twin?.assets?.length ??
                        0}
                    </strong>

                    <span>tracked assets</span>

                    <small>
                      Live asset intelligence
                    </small>
                  </div>

                  <div className="campaign-evidence-card">
                    <div className="campaign-evidence-label">
                      THREAT REPLAY
                    </div>

                    <strong>
                      {Array.isArray(investigation?.replay)
                        ? (investigation.replay ?? threatReplay?.timeline).length
                        : investigation?.replay?.events?.length ??
                          investigation?.replay?.timeline?.length ??
                          0}
                    </strong>

                    <span>replay events</span>

                    <small>
                      {investigation?.replay
                        ? "Replay available"
                        : "No replay linked"}
                    </small>
                  </div>

                </div>
              </section>

              <section className="campaign-card campaign-card-wide">
                <div className="campaign-card-title">
                  Intelligence Connections
                </div>

                <div className="campaign-overview-grid">
                  <div>
                    <span>Threat DNA</span>
                    <strong>
                      {investigation?.threat_dna
                        ? "CONNECTED"
                        : "AVAILABLE"}
                    </strong>
                  </div>

                  <div>
                    <span>Attack Graph</span>
                    <strong>
                      {investigation?.attack_graph
                        ? "CONNECTED"
                        : "AVAILABLE"}
                    </strong>
                  </div>

                  <div>
                    <span>Digital Twin</span>
                    <strong>
                      {investigation?.digital_twin
                        ? "CONNECTED"
                        : "AVAILABLE"}
                    </strong>
                  </div>

                  <div>
                    <span>Threat Replay</span>
                    <strong>
                      {investigation?.replay
                        ? "CONNECTED"
                        : "AVAILABLE"}
                    </strong>
                  </div>
                </div>

                <div className="campaign-tags" style={{ marginTop: 16 }}>
                  <span>
                    Campaign ? Cluster
                  </span>

                  {investigation?.cluster && (
                    <span>
                      Cluster ? Events
                    </span>
                  )}

                  {investigation?.attack_graph && (
                    <span>
                      Campaign ? Attack Graph
                    </span>
                  )}

                  {investigation?.digital_twin && (
                    <span>
                      Campaign ? Digital Twin
                    </span>
                  )}

                  {investigation?.replay && (
                    <span>
                      Campaign ? Replay

                    <div style={{ display: "flex", gap: "8px", alignItems: "center", marginTop: "8px" }}>
                      <button
                        type="button"
                        disabled={replayIndex <= 0}
                        onClick={() => loadReplayStep(replayIndex - 1)}
                      >
                        Previous
                      </button>

                      <span>
                        Step {replayIndex + 1} / {replayStepData?.count ?? threatReplay?.count ?? 0}
                      </span>

                      <button
                        type="button"
                        disabled={
                          replayIndex >=
                          ((replayStepData?.count ?? threatReplay?.count ?? 0) - 1)
                        }
                        onClick={() => loadReplayStep(replayIndex + 1)}
                      >
                        Next
                      </button>
                    </div>

                    {replayStepData?.event && (
                      <div style={{ marginTop: "8px" }}>
                        <strong>{replayStepData.event.category}</strong>
                        {" ? "}
                        {replayStepData.event.stage}
                      </div>
                    )}
                    </span>
                  )}
                </div>
              </section>

              <section className="campaign-card campaign-card-wide">
                <div className="campaign-card-header-row">
                  <div className="campaign-card-title">
                    ?? Digital Forensics & Evidence Integrity
                  </div>
                </div>

                {forensicLoading ? (
                  <div className="campaign-loading">
                    Loading forensic investigation...
                  </div>
                ) : forensicInvestigation?.success ? (
                  <div className="campaign-intel-grid">
                    <div className="campaign-intel-item">
                      <span>Incident</span>
                      <strong>
                        {forensicInvestigation.incident_id || selectedId}
                      </strong>
                    </div>

                    <div className="campaign-intel-item">
                      <span>Evidence Collected</span>
                      <strong>
                        {forensicInvestigation.evidence_count || 0}
                      </strong>
                    </div>

                    <div className="campaign-intel-item">
                      <span>Investigation Status</span>
                      <strong>
                        {forensicInvestigation.investigation_status || "pending"}
                      </strong>
                    </div>

                    <div className="campaign-intel-item">
                      <span>Evidence Integrity</span>
                      <strong>
                        {forensicInvestigation.evidence_integrity || "unknown"}
                      </strong>
                    </div>
                  </div>
                ) : (
                  <div className="campaign-empty">
                    No forensic evidence is currently available for this campaign.
                  </div>
                )}

                {forensicInvestigation?.evidence?.length > 0 && (
                  <div
                    style={{
                      marginTop: 20,
                      maxHeight: 420,
                      overflowY: "auto",
                    }}
                  >
                    {forensicInvestigation.evidence.map((item) => (
                      <div
                        key={item.id}
                        className="campaign-card"
                        style={{ marginBottom: 12 }}
                      >
                        <div className="campaign-card-header-row">
                          <strong>
                            {item.artifact_name || "Evidence Artifact"}
                          </strong>

                          <span>
                            {item.artifact_type || "artifact"}
                          </span>
                        </div>

                        <div className="campaign-intel-grid">
                          <div className="campaign-intel-item">
                            <span>SHA-256 Integrity</span>
                            <strong>
                              {item.integrity?.status ||
                                item.evidence_integrity?.status ||
                                "unknown"}
                            </strong>
                          </div>

                          <div className="campaign-intel-item">
                            <span>Custody Events</span>
                            <strong>
                              {item.custody?.length || 0}
                            </strong>
                          </div>

                          <div className="campaign-intel-item">
                            <span>Chain Status</span>
                            <strong>
                              {item.custody_integrity?.status || "unknown"}
                            </strong>
                          </div>

                          <div className="campaign-intel-item">
                            <span>Chain Verified</span>
                            <strong>
                              {item.custody_integrity?.verified
                                ? "VERIFIED"
                                : "PENDING"}
                            </strong>
                          </div>
                        </div>

                        {item.sha256 && (
                          <div
                            style={{
                              marginTop: 14,
                              fontFamily: "monospace",
                              fontSize: 12,
                              wordBreak: "break-all",
                            }}
                          >
                            SHA-256: {item.sha256}
                          </div>
                        )}

                        {item.custody?.length > 0 && (
                          <div style={{ marginTop: 16 }}>
                            <strong>Chain of Custody</strong>

                            {item.custody.map((event) => (
                              <div
                                key={event.id}
                                style={{
                                  marginTop: 10,
                                  paddingTop: 10,
                                  borderTop:
                                    "1px solid rgba(255,255,255,0.08)",
                                }}
                              >
                                <strong>{event.action}</strong>

                                <div>
                                  {event.from_custodian || "Unknown"} ?{" "}
                                  {event.to_custodian || "Unknown"}
                                </div>

                                {event.location && (
                                  <small>
                                    Location: {event.location}
                                  </small>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {selectedEvent && (
                <section className="campaign-card campaign-card-wide campaign-event-inspector">
                  <div className="campaign-card-header-row">
                    <div className="campaign-card-title">
                      Event Evidence Inspector
                    </div>

                    <button
                      type="button"
                      className="campaign-inspector-close"
                      onClick={() => setSelectedEvent(null)}
                    >
                      Close
                    </button>
                  </div>

                  {eventLoading ? (
                    <div className="campaign-loading">
                      Loading security event...
                    </div>
                  ) : (
                    <>
                      <div className="campaign-inspector-grid">
                        <div>
                          <span>Event ID</span>
                          <strong>
                            {selectedEvent.event_id || "?"}
                          </strong>
                        </div>

                        <div>
                          <span>Event Type</span>
                          <strong>
                            {selectedEvent.event_type || "?"}
                          </strong>
                        </div>

                        <div>
                          <span>Threat</span>
                          <strong>
                            {selectedEvent.threat_category || "?"}
                          </strong>
                        </div>

                        <div>
                          <span>Risk</span>
                          <strong>
                            {Number(
                              selectedEvent.risk_score || 0
                            ).toFixed(1)}
                          </strong>
                        </div>

                        <div>
                          <span>Severity</span>
                          <strong>
                            {selectedEvent.severity || "?"}
                          </strong>
                        </div>

                        <div>
                          <span>Status</span>
                          <strong>
                            {selectedEvent.status || "?"}
                          </strong>
                        </div>

                        <div>
                          <span>User</span>
                          <strong>
                            {selectedEvent.user || "?"}
                          </strong>
                        </div>

                        <div>
                          <span>IP</span>
                          <strong>
                            {selectedEvent.ip || "?"}
                          </strong>
                        </div>
                      </div>

                      <div className="campaign-inspector-json">
                        <div className="campaign-card-title">
                          Raw Security Event
                        </div>

                        <pre>
                          {JSON.stringify(
                            selectedEvent,
                            null,
                            2
                          )}
                        </pre>
                      </div>
                    </>
                  )}
                </section>
              )}

              <section className="campaign-card">
                <div className="campaign-card-header-row">
                  <div className="campaign-card-title">
                    Campaign Graph
                  </div>

                  <span>
                    {selectedEdges.length} relationships
                  </span>
                </div>

                <div className="campaign-graph">
                  <div className="campaign-node campaign-node-root">
                    <span>CAMPAIGN</span>
                    <strong>
                      {selectedCampaign.campaign_id}
                    </strong>
                  </div>

                  <div className="campaign-graph-column">
                    {eventEdges.map((edge) => (
                      <div
                        className="campaign-graph-node"
                        key={edge.id}
                      >
                        <span>EVENT</span>
                        <strong>
                          {edge.metadata
                            ? JSON.parse(edge.metadata)
                                ?.event_type ||
                              edge.target_id
                            : edge.target_id}
                        </strong>
                      </div>
                    ))}

                    {mitreEdges.map((edge) => (
                      <div
                        className="campaign-graph-node mitre"
                        key={edge.id}
                      >
                        <span>MITRE</span>
                        <strong>{edge.target_id}</strong>
                      </div>
                    ))}

                    {(selectedCampaign.affected_users || []).map(
                      (item) => (
                        <div
                          className="campaign-graph-node entity"
                          key={`user-${item}`}
                        >
                          <span>USER</span>
                          <strong>{item}</strong>
                        </div>
                      )
                    )}

                    {(selectedCampaign.affected_devices || []).map(
                      (item) => (
                        <div
                          className="campaign-graph-node entity"
                          key={`device-${item}`}
                        >
                          <span>DEVICE</span>
                          <strong>{item}</strong>
                        </div>
                      )
                    )}

                    {(selectedCampaign.affected_ips || []).map(
                      (item) => (
                        <div
                          className="campaign-graph-node entity"
                          key={`ip-${item}`}
                        >
                          <span>IP</span>
                          <strong>{item}</strong>
                        </div>
                      )
                    )}
                  </div>
                </div>
              </section>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
