from pathlib import Path

path = Path(r".\src\AdminSOC.jsx")
text = path.read_text(encoding="utf-8")

# ---------------------------------------------------------
# 1. Add selected admin panel state
# ---------------------------------------------------------
old = '''  const [lastAction, setLastAction] = useState("System ready");

  const runAdminAction = (action, callback) => {'''

new = '''  const [lastAction, setLastAction] = useState("System ready");
  const [activeAdminPanel, setActiveAdminPanel] = useState(null);

  const openAdminPanel = (panel) => {
    setActiveAdminPanel(panel);
  };

  const closeAdminPanel = () => {
    setActiveAdminPanel(null);
  };

  const runAdminAction = (action, callback) => {'''

if old not in text:
    raise SystemExit("ERROR: Could not find admin state section.")

text = text.replace(old, new, 1)

# ---------------------------------------------------------
# 2. Wire the TOP Control Center buttons
# ---------------------------------------------------------

replacements = [
(
'''              <button className="admin-control-button">
                Manage Permissions
              </button>''',
'''              <button
                className="admin-control-button"
                type="button"
                onClick={() => openAdminPanel("permissions")}
              >
                Manage Permissions
              </button>'''
),
(
'''              <button className="admin-control-button">
                Manage Tenants
              </button>''',
'''              <button
                className="admin-control-button"
                type="button"
                onClick={() => openAdminPanel("tenants")}
              >
                Manage Tenants
              </button>'''
),
(
'''              <button className="admin-control-button">
                Security Policies
              </button>''',
'''              <button
                className="admin-control-button"
                type="button"
                onClick={() => openAdminPanel("security")}
              >
                Security Policies
              </button>'''
),
(
'''              <button className="admin-control-button">
                SOC Configuration
              </button>''',
'''              <button
                className="admin-control-button"
                type="button"
                onClick={() => openAdminPanel("soc")}
              >
                SOC Configuration
              </button>'''
),
(
'''              <button className="admin-control-button">
                System Settings
              </button>''',
'''              <button
                className="admin-control-button"
                type="button"
                onClick={() => openAdminPanel("system")}
              >
                System Settings
              </button>'''
),
(
'''              <button className="admin-control-button">
                Open Audit Center
              </button>''',
'''              <button
                className="admin-control-button"
                type="button"
                onClick={() => openAdminPanel("audit")}
              >
                Open Audit Center
              </button>'''
),
]

for old, new in replacements:
    if old not in text:
        raise SystemExit(f"ERROR: Could not find expected button:\n{old}")
    text = text.replace(old, new, 1)

# ---------------------------------------------------------
# 3. Wire the SECOND Control Center buttons
# ---------------------------------------------------------

old = '''                <button className="admin-action-button" type="button">
                  Manage Tenants
                </button>'''

new = '''                <button
                  className="admin-action-button"
                  type="button"
                  onClick={() => openAdminPanel("tenants")}
                >
                  Manage Tenants
                </button>'''

if old not in text:
    raise SystemExit("ERROR: Could not find second Manage Tenants button.")

text = text.replace(old, new, 1)

old = '''                <button className="admin-action-button" type="button">
                  Configure
                </button>'''

new = '''                <button
                  className="admin-action-button"
                  type="button"
                  onClick={() => openAdminPanel("security")}
                >
                  Configure
                </button>'''

if old not in text:
    raise SystemExit("ERROR: Could not find Detection Policies Configure button.")

text = text.replace(old, new, 1)

# ---------------------------------------------------------
# 4. Replace audit self-scroll with actual panel
# ---------------------------------------------------------

old = '''                  onClick={() => navigateAdmin("admin-audit-center")}
                >
                  View Logs'''

new = '''                  onClick={() => openAdminPanel("audit")}
                >
                  View Logs'''

if old not in text:
    raise SystemExit("ERROR: Could not find View Logs action.")

text = text.replace(old, new, 1)

# ---------------------------------------------------------
# 5. Replace enterprise upgrade self-scroll
# ---------------------------------------------------------

old = '''                onClick={() => navigateAdmin("enterprise-upgrade")}
              >
                Explore Enterprise Upgrade'''

new = '''                onClick={() => openAdminPanel("enterprise")}
              >
                Explore Enterprise Upgrade'''

if old not in text:
    raise SystemExit("ERROR: Could not find Enterprise Upgrade action.")

text = text.replace(old, new, 1)

# ---------------------------------------------------------
# 6. Insert actionable modal immediately before main return
# ---------------------------------------------------------

marker = '''  return (
    <div className="admin-soc-page">'''

modal = '''  const renderAdminPanel = () => {
    if (!activeAdminPanel) return null;

    const panels = {
      permissions: {
        title: "Manage Permissions",
        subtitle: "Identity, role and administrative access controls.",
        items: [
          ["Super Admin", "Full platform administration"],
          ["Executive", "Executive security visibility"],
          ["SOC Analyst", "Threat investigation and response"],
          ["Customer", "Tenant-scoped security access"],
        ],
      },
      tenants: {
        title: "Manage Tenants",
        subtitle: "Enterprise tenant governance and isolation.",
        items: [
          ["Tenant Isolation", controls.tenantIsolation ? "ACTIVE" : "DISABLED"],
          ["Tenant Security Policies", "ENFORCED"],
          ["Tenant Administration", "READY"],
          ["Cross-Tenant Access", "RESTRICTED"],
        ],
      },
      security: {
        title: "Security Policies",
        subtitle: "Configure SafeChat AI detection and enforcement behavior.",
        items: [
          ["Real-Time Detection", controls.realtimeAlerts ? "ACTIVE" : "DISABLED"],
          ["Threat Escalation", controls.threatEscalation ? "ACTIVE" : "DISABLED"],
          ["Automatic Threat Blocking", "READY"],
          ["AI Remediation", autonomousAI ? "ACTIVE" : "DISABLED"],
        ],
      },
      soc: {
        title: "SOC Configuration",
        subtitle: "Security operations, alerting and automated response.",
        items: [
          ["Real-Time Alerts", controls.realtimeAlerts ? "ACTIVE" : "DISABLED"],
          ["AI Remediation", autonomousAI ? "ACTIVE" : "DISABLED"],
          ["Lockdown Mode", lockdownMode ? "ACTIVE" : "DISABLED"],
          ["SOC Platform", "OPERATIONAL"],
        ],
      },
      system: {
        title: "System Settings",
        subtitle: "SafeChat AI platform operational configuration.",
        items: [
          ["API", "OPERATIONAL"],
          ["WebSocket", "OPERATIONAL"],
          ["Environment", "PRODUCTION"],
          ["Maintenance Mode", maintenanceMode ? "ACTIVE" : "DISABLED"],
        ],
      },
      audit: {
        title: "Audit Center",
        subtitle: "Administrative activity and security governance.",
        items: [
          ["Audit Logging", controls.auditLogging ? "ACTIVE" : "DISABLED"],
          ["Security Events", "MONITORED"],
          ["Administrative Actions", "RECORDED"],
          ["Governance Changes", "TRACKED"],
        ],
      },
      enterprise: {
        title: "Enterprise Upgrade",
        subtitle: "Advanced SafeChat AI SOC capabilities.",
        items: [
          ["Advanced Threat Intelligence", "AVAILABLE"],
          ["Automated Incident Response", "AVAILABLE"],
          ["Enterprise Governance", "AVAILABLE"],
          ["Extended Audit Controls", "AVAILABLE"],
        ],
      },
    };

    const panel = panels[activeAdminPanel];

    if (!panel) return null;

    return (
      <div
        role="dialog"
        aria-modal="true"
        aria-label={panel.title}
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 9999,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 20,
          background: "rgba(2,6,23,0.78)",
          backdropFilter: "blur(6px)",
        }}
        onClick={closeAdminPanel}
      >
        <div
          style={{
            width: "min(720px, 100%)",
            maxHeight: "85vh",
            overflowY: "auto",
            background: "#0f172a",
            border: "1px solid #334155",
            borderRadius: 16,
            padding: 24,
            boxShadow: "0 25px 80px rgba(0,0,0,0.55)",
          }}
          onClick={(event) => event.stopPropagation()}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
              gap: 20,
              marginBottom: 20,
            }}
          >
            <div>
              <div
                style={{
                  color: "#00ffc8",
                  fontSize: 12,
                  fontWeight: 800,
                  letterSpacing: 1,
                  marginBottom: 6,
                }}
              >
                ADMIN CONTROL
              </div>

              <h2 style={{ margin: 0, color: "#f8fafc" }}>
                {panel.title}
              </h2>

              <p
                style={{
                  margin: "8px 0 0",
                  color: "#94a3b8",
                }}
              >
                {panel.subtitle}
              </p>
            </div>

            <button
              type="button"
              onClick={closeAdminPanel}
              style={{
                border: "1px solid #475569",
                background: "#111827",
                color: "#cbd5e1",
                borderRadius: 8,
                padding: "8px 12px",
                cursor: "pointer",
                fontWeight: 700,
              }}
            >
              Close
            </button>
          </div>

          <div
            style={{
              display: "grid",
              gap: 10,
            }}
          >
            {panel.items.map(([name, status]) => (
              <div
                key={name}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: 20,
                  padding: 15,
                  background: "#020617",
                  border: "1px solid #1e293b",
                  borderRadius: 10,
                }}
              >
                <div>
                  <strong style={{ color: "#e2e8f0" }}>
                    {name}
                  </strong>
                </div>

                <span
                  style={{
                    color: "#00ffc8",
                    fontSize: 12,
                    fontWeight: 800,
                    whiteSpace: "nowrap",
                  }}
                >
                  {status}
                </span>
              </div>
            ))}
          </div>

          <div
            style={{
              marginTop: 20,
              padding: 14,
              background: "rgba(0,255,200,0.06)",
              border: "1px solid rgba(0,255,200,0.18)",
              borderRadius: 10,
              color: "#94a3b8",
              fontSize: 13,
            }}
          >
            Control panel loaded successfully. Backend persistence and
            enforcement will be connected in the next phase.
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="admin-soc-page">
      {renderAdminPanel()}'''

if marker not in text:
    raise SystemExit("ERROR: Could not find AdminSOC return marker.")

text = text.replace(marker, modal, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("Admin Control Center actions patched successfully.")
