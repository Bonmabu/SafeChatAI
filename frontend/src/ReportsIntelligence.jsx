import { useState } from "react";
import axios from "axios";

const API = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function ReportsIntelligence() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [aiReport, setAiReport] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  const runQuery = async (value = query) => {
    const text = value.trim();

    if (!text) return;

    setLoading(true);
    setError("");

    try {
      const response = await axios.get(
        `${API}/reports/query`,
        {
          params: { q: text },
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );

      setResult(response.data);
    } catch (err) {
      console.error("REPORT QUERY ERROR:", err);

      setError(
        err.response?.data?.detail ||
        "Unable to generate the requested report."
      );
    } finally {
      setLoading(false);
    }
  };

  const loadAIInvestigation = async (incidentId) => {
    setAiLoading(true);
    setError("");

    try {
      const response = await axios.get(
        `${API}/reports/${incidentId}/ai-investigation`,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );

      setAiReport(response.data);
    } catch (err) {
      console.error("AI INVESTIGATION REPORT ERROR:", err);

      setError(
        err.response?.data?.detail ||
        "Unable to load the AI investigation report."
      );
    } finally {
      setAiLoading(false);
    }
  };

  const quickReports = [
    "Generate an executive report",
    "Show phishing incidents",
    "Show all high-risk incidents this month",
    "Retrieve an incident report",
  ];

  return (
    <div
      style={{
        minHeight: "calc(100vh - 90px)",
        padding: "28px",
        background:
          "radial-gradient(circle at top right, rgba(0,255,200,0.07), transparent 35%), #020617",
        color: "#f8fafc",
      }}
    >
      <div
        style={{
          maxWidth: 1500,
          margin: "0 auto",
        }}
      >
        <div style={{ marginBottom: 30 }}>
          <div
            style={{
              color: "#00ffc8",
              fontSize: 12,
              fontWeight: 800,
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              marginBottom: 8,
            }}
          >
            SafeChat Intelligence Center
          </div>

          <h1
            style={{
              margin: 0,
              fontSize: 34,
              fontWeight: 800,
              letterSpacing: "-0.03em",
            }}
          >
            Reports & Intelligence
          </h1>

          <p
            style={{
              marginTop: 10,
              color: "#94a3b8",
              fontSize: 15,
              maxWidth: 720,
            }}
          >
            Turn SOC activity into intelligence, evidence and decisions.
          </p>
        </div>

        <section
          style={{
            padding: 24,
            borderRadius: 18,
            background:
              "linear-gradient(145deg, rgba(15,23,42,0.96), rgba(15,23,42,0.72))",
            border: "1px solid rgba(148,163,184,0.14)",
            boxShadow: "0 20px 60px rgba(0,0,0,0.28)",
            marginBottom: 24,
          }}
        >
          <div
            style={{
              fontSize: 13,
              color: "#00ffc8",
              fontWeight: 800,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              marginBottom: 10,
            }}
          >
            Ask SafeChat
          </div>

          <div
            style={{
              display: "flex",
              gap: 12,
              alignItems: "stretch",
            }}
          >
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runQuery();
              }}
              placeholder='Ask for a report, e.g. "Show phishing incidents for August"'
              style={{
                flex: 1,
                minWidth: 0,
                padding: "15px 17px",
                borderRadius: 12,
                border: "1px solid #334155",
                background: "#020617",
                color: "#f8fafc",
                outline: "none",
                fontSize: 14,
              }}
            />

            <button
              type="button"
              onClick={() => runQuery()}
              disabled={loading}
              style={{
                padding: "0 22px",
                borderRadius: 12,
                border: "1px solid rgba(0,255,200,0.35)",
                background: "rgba(0,255,200,0.12)",
                color: "#00ffc8",
                fontWeight: 800,
                cursor: loading ? "wait" : "pointer",
                whiteSpace: "nowrap",
              }}
            >
              {loading ? "Generating..." : "Generate Intelligence"}
            </button>
          </div>

          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 8,
              marginTop: 14,
            }}
          >
            {quickReports.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => {
                  setQuery(item);
                  runQuery(item);
                }}
                style={{
                  padding: "8px 12px",
                  borderRadius: 999,
                  border: "1px solid #334155",
                  background: "#0f172a",
                  color: "#cbd5e1",
                  cursor: "pointer",
                  fontSize: 12,
                }}
              >
                {item}
              </button>
            ))}
          </div>

          {error && (
            <div
              style={{
                marginTop: 16,
                padding: 12,
                borderRadius: 10,
                background: "rgba(239,68,68,0.08)",
                border: "1px solid rgba(239,68,68,0.25)",
                color: "#fca5a5",
              }}
            >
              {error}
            </div>
          )}
        </section>

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "repeat(auto-fit, minmax(210px, 1fr))",
            gap: 14,
            marginBottom: 24,
          }}
        >
          {[
            ["REPORT ENGINE", "ACTIVE", "Natural-language intelligence"],
            ["TENANT ISOLATION", "SECURE", "Authenticated reporting"],
            ["EVIDENCE", "READY", "Forensic report integration"],
            ["AI LAYER", "ONLINE", "Investigation-ready architecture"],
          ].map(([label, value, description]) => (
            <div
              key={label}
              style={{
                padding: 20,
                borderRadius: 16,
                background: "#0f172a",
                border: "1px solid #1e293b",
              }}
            >
              <div
                style={{
                  color: "#64748b",
                  fontSize: 10,
                  fontWeight: 800,
                  letterSpacing: "0.12em",
                }}
              >
                {label}
              </div>

              <div
                style={{
                  marginTop: 10,
                  fontSize: 22,
                  fontWeight: 800,
                  color: "#00ffc8",
                }}
              >
                {value}
              </div>

              <div
                style={{
                  marginTop: 5,
                  color: "#94a3b8",
                  fontSize: 12,
                }}
              >
                {description}
              </div>
            </div>
          ))}
        </div>

        {result && (
          <section
            style={{
              padding: 24,
              borderRadius: 18,
              background: "#0f172a",
              border: "1px solid #1e293b",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 15,
                alignItems: "center",
                marginBottom: 20,
              }}
            >
              <div>
                <div
                  style={{
                    color: "#64748b",
                    fontSize: 11,
                    fontWeight: 800,
                    letterSpacing: "0.12em",
                    textTransform: "uppercase",
                  }}
                >
                  Intelligence Result
                </div>

                <h2
                  style={{
                    margin: "7px 0 0",
                    fontSize: 22,
                  }}
                >
                  {result.query}
                </h2>
              </div>

              <div
                style={{
                  padding: "8px 12px",
                  borderRadius: 999,
                  background: "rgba(0,255,200,0.08)",
                  color: "#00ffc8",
                  fontSize: 12,
                  fontWeight: 800,
                }}
              >
                {result.result_count ?? 0} RESULTS
              </div>
            </div>

            {result.reports?.length > 0 ? (
              <div
                style={{
                  display: "grid",
                  gap: 8,
                }}
              >
                {result.reports.map((report) => (
                  <div
                    key={report.id}
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "120px minmax(120px,1fr) 120px 120px 170px 150px",
                      gap: 14,
                      alignItems: "center",
                      padding: "14px 16px",
                      borderRadius: 12,
                      background: "#020617",
                      border: "1px solid #1e293b",
                    }}
                  >
                    <strong>INC-{report.id}</strong>
                    <span>{report.category || "Unknown"}</span>
                    <span>{report.severity || "—"}</span>
                    <span>{report.status || "—"}</span>
                    <span
                      style={{
                        color: "#64748b",
                        fontSize: 12,
                      }}
                    >
                      {report.created_at || "—"}
                    </span>

                    <button
                      type="button"
                      onClick={() => loadAIInvestigation(report.id)}
                      disabled={aiLoading}
                      style={{
                        padding: "7px 10px",
                        borderRadius: 8,
                        border: "1px solid rgba(0,255,200,0.25)",
                        background: "rgba(0,255,200,0.06)",
                        color: "#00ffc8",
                        cursor: aiLoading ? "wait" : "pointer",
                        fontSize: 11,
                        fontWeight: 800,
                        whiteSpace: "nowrap",
                      }}
                    >
                      {aiLoading ? "Loading..." : "AI Investigation"}
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  padding: 30,
                  textAlign: "center",
                  color: "#64748b",
                }}
              >
                No matching reports found.
              </div>
            )}
          </section>
        )}
        {aiReport?.ai_investigation && (
          <section
            style={{
              marginTop: 24,
              padding: 24,
              borderRadius: 18,
              background: "#0f172a",
              border: "1px solid #1e293b",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 16,
                alignItems: "flex-start",
                marginBottom: 20,
              }}
            >
              <div>
                <div
                  style={{
                    color: "#00ffc8",
                    fontSize: 11,
                    fontWeight: 800,
                    letterSpacing: "0.12em",
                  }}
                >
                  PHASE 39 · AI INVESTIGATION
                </div>

                <h2
                  style={{
                    margin: "7px 0 0",
                    fontSize: 24,
                  }}
                >
                  Investigation {aiReport.ai_investigation.investigation_id}
                </h2>

                <div
                  style={{
                    marginTop: 6,
                    color: "#94a3b8",
                    fontSize: 13,
                  }}
                >
                  Incident {aiReport.ai_investigation.incident_id}
                  {" · "}
                  {aiReport.ai_investigation.category || "Unknown"}
                </div>
              </div>

              <div
                style={{
                  padding: "8px 12px",
                  borderRadius: 999,
                  background: "rgba(239,68,68,0.10)",
                  border: "1px solid rgba(239,68,68,0.20)",
                  color: "#fca5a5",
                  fontSize: 11,
                  fontWeight: 800,
                }}
              >
                {aiReport.ai_investigation.severity || "UNKNOWN"}
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns:
                  "repeat(auto-fit, minmax(150px, 1fr))",
                gap: 12,
                marginBottom: 24,
              }}
            >
              {[
                ["RISK SCORE", aiReport.ai_investigation.risk_score ?? "—"],
                ["CONFIDENCE", `${aiReport.ai_investigation.confidence ?? 0}%`],
                ["PRIORITY", aiReport.ai_investigation.priority || "—"],
                ["RELATED", aiReport.ai_investigation.related_incidents ?? 0],
              ].map(([label, value]) => (
                <div
                  key={label}
                  style={{
                    padding: 16,
                    borderRadius: 12,
                    background: "#020617",
                    border: "1px solid #1e293b",
                  }}
                >
                  <div
                    style={{
                      color: "#64748b",
                      fontSize: 10,
                      fontWeight: 800,
                      letterSpacing: "0.10em",
                    }}
                  >
                    {label}
                  </div>

                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 20,
                      fontWeight: 800,
                      color: "#f8fafc",
                    }}
                  >
                    {value}
                  </div>
                </div>
              ))}
            </div>

            {[
              ["FINDINGS", aiReport.ai_investigation.findings],
              ["EVIDENCE", aiReport.ai_investigation.evidence],
              [
                "RECOMMENDED ACTIONS",
                aiReport.ai_investigation.recommended_actions,
              ],
            ].map(([title, items]) => (
              <div key={title} style={{ marginBottom: 22 }}>
                <div
                  style={{
                    color: "#94a3b8",
                    fontSize: 11,
                    fontWeight: 800,
                    letterSpacing: "0.12em",
                    marginBottom: 9,
                  }}
                >
                  {title}
                </div>

                <div
                  style={{
                    display: "grid",
                    gap: 7,
                  }}
                >
                  {(items || []).map((item, index) => (
                    <div
                      key={`${title}-${index}`}
                      style={{
                        padding: "10px 12px",
                        borderRadius: 10,
                        background: "#020617",
                        border: "1px solid #1e293b",
                        color: "#cbd5e1",
                        fontSize: 13,
                        lineHeight: 1.5,
                      }}
                    >
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            ))}

            <div
              style={{
                paddingTop: 16,
                borderTop: "1px solid #1e293b",
                color: "#64748b",
                fontSize: 12,
              }}
            >
              MITRE: {aiReport.ai_investigation.mitre || "Not mapped"}
              {" · "}
              Agent: {aiReport.ai_investigation.agent || "SafeChat Investigation Agent"}
              {" · "}
              Status: {aiReport.ai_investigation.status || "Unknown"}
            </div>
          </section>
        )}

      </div>
    </div>
  );
}


