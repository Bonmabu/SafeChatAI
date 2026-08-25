import { useState } from "react";
import "./AdminSOC.css";
import AdminUserMetrics from "./AdminUserMetrics";
import AdminUserDirectory from "./AdminUserDirectory";

export default function AdminSOC() {

  const [superAdminMode, setSuperAdminMode] = useState(true);
  const [lockdownMode, setLockdownMode] = useState(false);
  const [autonomousAI, setAutonomousAI] = useState(true);
  const [maintenanceMode, setMaintenanceMode] = useState(false);
  const [lastAction, setLastAction] = useState("System ready");

  const runAdminAction = (action, callback) => {
    const confirmed = window.confirm(
      `Super Admin Action\n\n${action}\n\nContinue?`
    );

    if (!confirmed) return;

    callback();
    setLastAction(action);
  };

  const refreshAdminSOC = () => {
    window.location.reload();
  };


  const navigateAdmin = (target) => {
    const element = document.getElementById(target);

    if (element) {
      element.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }
  };

  const [controls, setControls] = useState({
    enforceMFA: true,
    sessionProtection: true,
    threatEscalation: true,
    auditLogging: true,
    tenantIsolation: true,
    realtimeAlerts: true,
  });

  const toggleControl = (key) => {
    setControls((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };
  return (
    <div className="admin-soc-page">

      {/* COMMAND HEADER */}
      <section className="admin-command-header">
        <div className="admin-header-glow" />

        <div className="admin-header-content">
          <div className="admin-header-main">

            <div className="admin-eyebrow">
              <span className="admin-live-dot" />
              ADMIN SECURITY OPERATIONS
            </div>

            <h1 className="admin-title">
              <span className="admin-title-icon">🛡️</span>
              SafeChat AI
              <span className="admin-title-muted">
                {" "}SOC Command Center
              </span>
            </h1>

            <p className="admin-subtitle">
              Enterprise identity, access, tenant governance and security
              operations unified into one control surface.
            </p>

          </div>

          <div className="admin-status-card">
            <div className="admin-status-icon">✓</div>

            <div>
              <div className="admin-status-label">
                Control Status
              </div>

              <div className="admin-status-value">
                <span />
                OPERATIONAL
              </div>
            </div>
          </div>
        </div>

        <div className="admin-header-meta">

          <div className="admin-meta-item">
            <span className="admin-meta-label">ENVIRONMENT</span>
            <strong>PRODUCTION</strong>
          </div>

          <div className="admin-meta-divider" />

          <div className="admin-meta-item">
            <span className="admin-meta-label">SECURITY MODE</span>
            <strong>ACTIVE</strong>
          </div>

          <div className="admin-meta-divider" />

          <div className="admin-meta-item">
            <span className="admin-meta-label">ACCESS</span>
            <strong>ADMINISTRATOR</strong>
          </div>

          <div className="admin-meta-spacer" />

          <div className="admin-secure-badge">
            SECURE CONTROL PLANE
          </div>

        </div>
      </section>


      {/* SUPER ADMIN COMMAND CENTER */}
      <section id="super-admin-command" className="admin-section super-admin-section">

        <div className="admin-section-heading">
          <div>
            <span className="admin-section-kicker">
              SUPER ADMIN CONTROL
            </span>

            <h2>Super Admin Command Center</h2>

            <p>
              High-privilege security, AI, availability and emergency
              operational controls.
            </p>
          </div>

          <div className={`super-admin-status ${superAdminMode ? "active" : "disabled"}`}>
            <span />
            {superAdminMode ? "SUPER ADMIN ACTIVE" : "SUPER ADMIN DISABLED"}
          </div>
        </div>

        <div className="super-admin-grid">

          <div className="super-admin-card">
            <div className="super-admin-card-top">
              <div className="super-admin-icon">👑</div>
              <div>
                <h3>Super Admin Mode</h3>
                <p>Enable privileged administrative operations.</p>
              </div>
            </div>

            <button
              type="button"
              className={`admin-toggle large ${superAdminMode ? "active" : ""}`}
              onClick={() =>
                runAdminAction(
                  superAdminMode
                    ? "Disable Super Admin Mode"
                    : "Enable Super Admin Mode",
                  () => setSuperAdminMode(!superAdminMode)
                )
              }
              disabled={!superAdminMode && false}
            >
              <span />
            </button>
          </div>

          <div className="super-admin-card danger">
            <div className="super-admin-card-top">
              <div className="super-admin-icon">🚨</div>
              <div>
                <h3>Global Lockdown</h3>
                <p>Restrict high-risk platform activity immediately.</p>
              </div>
            </div>

            <button
              type="button"
              className={`admin-toggle large ${lockdownMode ? "active danger-active" : ""}`}
              onClick={() =>
                runAdminAction(
                  lockdownMode
                    ? "Disable Global Lockdown"
                    : "ACTIVATE GLOBAL LOCKDOWN",
                  () => setLockdownMode(!lockdownMode)
                )
              }
            >
              <span />
            </button>
          </div>

          <div className="super-admin-card">
            <div className="super-admin-card-top">
              <div className="super-admin-icon">🤖</div>
              <div>
                <h3>Autonomous AI</h3>
                <p>Allow SafeChat AI to perform automated SOC decisions.</p>
              </div>
            </div>

            <button
              type="button"
              className={`admin-toggle large ${autonomousAI ? "active" : ""}`}
              onClick={() =>
                runAdminAction(
                  autonomousAI
                    ? "Disable Autonomous AI"
                    : "Enable Autonomous AI",
                  () => setAutonomousAI(!autonomousAI)
                )
              }
            >
              <span />
            </button>
          </div>

          <div className="super-admin-card warning">
            <div className="super-admin-card-top">
              <div className="super-admin-icon">🔧</div>
              <div>
                <h3>Maintenance Mode</h3>
                <p>Place the platform into controlled maintenance.</p>
              </div>
            </div>

            <button
              type="button"
              className={`admin-toggle large ${maintenanceMode ? "active warning-active" : ""}`}
              onClick={() =>
                runAdminAction(
                  maintenanceMode
                    ? "Disable Maintenance Mode"
                    : "Enable Maintenance Mode",
                  () => setMaintenanceMode(!maintenanceMode)
                )
              }
            >
              <span />
            </button>
          </div>

        </div>

        <div className="super-admin-command-bar">

          <div className="super-admin-last-action">
            <span className="command-label">LAST ADMINISTRATIVE ACTION</span>
            <strong>{lastAction}</strong>
          </div>

          <div className="super-admin-actions">

            <button
              type="button"
              className="admin-action-button"
              onClick={() =>
                runAdminAction(
                  "Refresh SafeChat AI Admin SOC",
                  refreshAdminSOC
                )
              }
            >
              ↻ Refresh SOC
            </button>

            <button
              type="button"
              className="admin-action-button"
              onClick={() =>
                navigateAdmin("identity-operations")
              }
            >
              Open SOC
            </button>

            <button
              type="button"
              className="admin-action-button"
              onClick={() =>
                navigateAdmin("admin-audit-center")
              }
            >
              Audit Center
            </button>

            <button
              type="button"
              className="admin-action-button"
              onClick={() =>
                navigateAdmin("enterprise-upgrade")
              }
            >
              Enterprise
            </button>

          </div>
        </div>

      </section>

      {/* ADMIN CONTROL CENTER */}
      <section id="identity-operations" className="admin-section">

        <div className="admin-section-heading compact">
          <div>
            <span className="admin-section-kicker">
              CONTROL CENTER
            </span>

            <h2>Security & Platform Controls</h2>

            <p>
              Centralized administrative controls for identity, tenants,
              detection, enforcement and platform operations.
            </p>
          </div>

          <div className="admin-section-indicator">
            <span />
            CONTROL READY
          </div>
        </div>

        <div className="admin-control-grid">

          <div className="admin-control-card">
            <div className="admin-control-icon">🔐</div>
            <div className="admin-control-content">
              <h3>Access Control</h3>
              <p>Manage authentication and administrative access policies.</p>

              <label className="admin-toggle-row">
                <span>Require MFA</span>
                <input type="checkbox" defaultChecked />
              </label>

              <label className="admin-toggle-row">
                <span>Session Protection</span>
                <input type="checkbox" defaultChecked />
              </label>

              <button className="admin-control-button">
                Manage Permissions
              </button>
            </div>
          </div>

          <div className="admin-control-card">
            <div className="admin-control-icon">🏢</div>
            <div className="admin-control-content">
              <h3>Tenant Governance</h3>
              <p>Control tenant isolation and enterprise security posture.</p>

              <label className="admin-toggle-row">
                <span>Tenant Isolation</span>
                <input type="checkbox" defaultChecked />
              </label>

              <label className="admin-toggle-row">
                <span>Tenant Security Policies</span>
                <input type="checkbox" defaultChecked />
              </label>

              <button className="admin-control-button">
                Manage Tenants
              </button>
            </div>
          </div>

          <div className="admin-control-card">
            <div className="admin-control-icon">🛡️</div>
            <div className="admin-control-content">
              <h3>Security Enforcement</h3>
              <p>Configure how SafeChat AI responds to detected threats.</p>

              <label className="admin-toggle-row">
                <span>Real-Time Detection</span>
                <input type="checkbox" defaultChecked />
              </label>

              <label className="admin-toggle-row">
                <span>Automatic Threat Blocking</span>
                <input type="checkbox" defaultChecked />
              </label>

              <button className="admin-control-button">
                Security Policies
              </button>
            </div>
          </div>

          <div className="admin-control-card">
            <div className="admin-control-icon">🚨</div>
            <div className="admin-control-content">
              <h3>SOC Operations</h3>
              <p>Configure alerting, escalation and AI-assisted response.</p>

              <label className="admin-toggle-row">
                <span>AI Remediation</span>
                <input type="checkbox" defaultChecked />
              </label>

              <label className="admin-toggle-row">
                <span>Alert Escalation</span>
                <input type="checkbox" defaultChecked />
              </label>

              <button className="admin-control-button">
                SOC Configuration
              </button>
            </div>
          </div>

          <div className="admin-control-card">
            <div className="admin-control-icon">⚙️</div>
            <div className="admin-control-content">
              <h3>System Operations</h3>
              <p>Monitor critical platform services and operational state.</p>

              <div className="admin-system-status">
                <span className="admin-system-dot" />
                API Operational
              </div>

              <div className="admin-system-status">
                <span className="admin-system-dot" />
                WebSocket Operational
              </div>

              <button className="admin-control-button">
                System Settings
              </button>
            </div>
          </div>

          <div className="admin-control-card">
            <div className="admin-control-icon">📋</div>
            <div className="admin-control-content">
              <h3>Audit & Compliance</h3>
              <p>Review administrative activity and security changes.</p>

              <div className="admin-audit-summary">
                <strong>Audit Logging</strong>
                <span>ACTIVE</span>
              </div>

              <div className="admin-audit-summary">
                <strong>Security Events</strong>
                <span>MONITORED</span>
              </div>

              <button className="admin-control-button">
                Open Audit Center
              </button>
            </div>
          </div>

        </div>

      </section>
      {/* USER INTELLIGENCE */}
      <section className="admin-section">

        <div className="admin-section-heading compact">
          <div>
            <span className="admin-section-kicker">
              IDENTITY INTELLIGENCE
            </span>

            <h2>User & Tenant Operations</h2>

            <p>
              Security posture, account activity and tenant-level visibility.
            </p>
          </div>
        </div>

        <div className="admin-metrics-panel">
          <AdminUserMetrics />
        </div>

        <div className="admin-directory-panel">
          <AdminUserDirectory />
        </div>

      </section>

      {/* ADMIN CONTROL CENTER */}
      <section className="admin-section">

        <div className="admin-section-heading compact">
          <div>
            <span className="admin-section-kicker">
              ADMIN CONTROL CENTER
            </span>

            <h2>Security & Governance Controls</h2>

            <p>
              Configure identity protection, tenant governance, security
              enforcement and enterprise SOC operations.
            </p>
          </div>

          <div className="admin-section-indicator">
            <span />
            CONTROL READY
          </div>
        </div>

        <div className="admin-control-grid">

          {/* IDENTITY SECURITY */}
          <div className="admin-control-card">
            <div className="admin-control-card-header">
              <div className="admin-control-icon">🔐</div>
              <div>
                <h3>Identity & Access</h3>
                <p>Enterprise authentication controls</p>
              </div>
            </div>

            <div className="admin-control-list">

              <div className="admin-control-row">
                <div>
                  <strong>Multi-Factor Authentication</strong>
                  <span>Require stronger authentication for privileged accounts.</span>
                </div>

                <button
                  className={`admin-toggle ${controls.enforceMFA ? "active" : ""}`}
                  onClick={() => toggleControl("enforceMFA")}
                  type="button"
                  aria-label="Toggle Multi-Factor Authentication"
                >
                  <span />
                </button>
              </div>

              <div className="admin-control-row">
                <div>
                  <strong>Session Protection</strong>
                  <span>Protect administrator sessions and access tokens.</span>
                </div>

                <button
                  className={`admin-toggle ${controls.sessionProtection ? "active" : ""}`}
                  onClick={() => toggleControl("sessionProtection")}
                  type="button"
                  aria-label="Toggle Session Protection"
                >
                  <span />
                </button>
              </div>

            </div>
          </div>

          {/* TENANT GOVERNANCE */}
          <div className="admin-control-card">
            <div className="admin-control-card-header">
              <div className="admin-control-icon">🏢</div>
              <div>
                <h3>Tenant Governance</h3>
                <p>Enterprise isolation and administration</p>
              </div>
            </div>

            <div className="admin-control-list">

              <div className="admin-control-row">
                <div>
                  <strong>Tenant Isolation</strong>
                  <span>Maintain security boundaries between organizations.</span>
                </div>

                <button
                  className={`admin-toggle ${controls.tenantIsolation ? "active" : ""}`}
                  onClick={() => toggleControl("tenantIsolation")}
                  type="button"
                  aria-label="Toggle Tenant Isolation"
                >
                  <span />
                </button>
              </div>

              <div className="admin-action-row">
                <div>
                  <strong>Tenant Management</strong>
                  <span>Create, review and govern enterprise tenants.</span>
                </div>

                <button className="admin-action-button" type="button">
                  Manage Tenants
                </button>
              </div>

            </div>
          </div>

          {/* SECURITY POLICY */}
          <div className="admin-control-card">
            <div className="admin-control-card-header">
              <div className="admin-control-icon">🛡️</div>
              <div>
                <h3>Security Enforcement</h3>
                <p>Automated SOC protection policies</p>
              </div>
            </div>

            <div className="admin-control-list">

              <div className="admin-control-row">
                <div>
                  <strong>Threat Escalation</strong>
                  <span>Escalate high-risk detections into SOC workflows.</span>
                </div>

                <button
                  className={`admin-toggle ${controls.threatEscalation ? "active" : ""}`}
                  onClick={() => toggleControl("threatEscalation")}
                  type="button"
                  aria-label="Toggle Threat Escalation"
                >
                  <span />
                </button>
              </div>

              <div className="admin-action-row">
                <div>
                  <strong>Detection Policies</strong>
                  <span>Manage threat scoring and enforcement rules.</span>
                </div>

                <button className="admin-action-button" type="button">
                  Configure
                </button>
              </div>

            </div>
          </div>

          {/* MONITORING */}
          <div className="admin-control-card">
            <div className="admin-control-card-header">
              <div className="admin-control-icon">📡</div>
              <div>
                <h3>Monitoring & Response</h3>
                <p>Real-time operational visibility</p>
              </div>
            </div>

            <div className="admin-control-list">

              <div className="admin-control-row">
                <div>
                  <strong>Real-Time Alerts</strong>
                  <span>Stream security events to the administrative SOC.</span>
                </div>

                <button
                  className={`admin-toggle ${controls.realtimeAlerts ? "active" : ""}`}
                  onClick={() => toggleControl("realtimeAlerts")}
                  type="button"
                  aria-label="Toggle Real-Time Alerts"
                >
                  <span />
                </button>
              </div>

              <div className="admin-action-row">
                <div>
                  <strong>Incident Operations</strong>
                  <span>Review and coordinate active security incidents.</span>
                </div>

                <button
                  className="admin-action-button"
                  type="button"
                  onClick={() => navigateAdmin("identity-operations")}
                >
                  Open SOC
                </button>
              </div>

            </div>
          </div>

          {/* AUDIT */}
          <div id="admin-audit-center" className="admin-control-card">
            <div className="admin-control-card-header">
              <div className="admin-control-icon">📜</div>
              <div>
                <h3>Audit & Compliance</h3>
                <p>Administrative activity and governance</p>
              </div>
            </div>

            <div className="admin-control-list">

              <div className="admin-control-row">
                <div>
                  <strong>Administrative Audit Log</strong>
                  <span>Record administrative actions and security changes.</span>
                </div>

                <button
                  className={`admin-toggle ${controls.auditLogging ? "active" : ""}`}
                  onClick={() => toggleControl("auditLogging")}
                  type="button"
                  aria-label="Toggle Administrative Audit Logging"
                >
                  <span />
                </button>
              </div>

              <div className="admin-action-row">
                <div>
                  <strong>Audit Center</strong>
                  <span>Review governance and security activity.</span>
                </div>

                <button
                  className="admin-action-button"
                  type="button"
                  onClick={() => navigateAdmin("admin-audit-center")}
                >
                  View Logs
                </button>
              </div>

            </div>
          </div>

          {/* UPGRADE */}
          <div id="enterprise-upgrade" className="admin-control-card admin-upgrade-card">
            <div className="admin-control-card-header">
              <div className="admin-control-icon">🚀</div>
              <div>
                <h3>Enterprise Upgrade</h3>
                <p>Expand SafeChat AI SOC capabilities</p>
              </div>
            </div>

            <div className="admin-upgrade-content">

              <div className="admin-plan-badge">
                ENTERPRISE SOC
              </div>

              <h3>Advanced Security Operations</h3>

              <p>
                Unlock advanced tenant governance, expanded threat
                intelligence, automated response and enterprise controls.
              </p>

              <div className="admin-upgrade-features">
                <span>✓ Advanced Threat Intelligence</span>
                <span>✓ Automated Incident Response</span>
                <span>✓ Enterprise Governance</span>
                <span>✓ Extended Audit Controls</span>
              </div>

              <button
                className="admin-upgrade-button"
                type="button"
                onClick={() => navigateAdmin("enterprise-upgrade")}
              >
                Explore Enterprise Upgrade
              </button>

            </div>
          </div>

        </div>

      </section>
      {/* FOOTER */}
      <footer className="admin-footer">

        <div>
          <strong>SafeChat AI SOC</strong>
          <span>Administrative Control Plane</span>
        </div>

        <div className="admin-footer-status">
          <span />
          All control systems operational
        </div>

      </footer>

    </div>
  );
}









