from pathlib import Path

jsx = Path(r".\frontend\src\AdminSOC.jsx")
css = Path(r".\frontend\src\AdminSOC.css")

text = jsx.read_text(encoding="utf-8-sig")

marker = '      {/* SYSTEM CONTROL SURFACE */}'

if "SUPER ADMIN COMMAND CENTER" not in text:
    panel = r'''
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
                navigateAdmin("soc-platform")
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

'''

    if marker not in text:
        raise SystemExit("SYSTEM CONTROL SURFACE marker not found.")

    text = text.replace(marker, panel + marker, 1)

jsx.write_text(text, encoding="utf-8", newline="\n")


css_text = css.read_text(encoding="utf-8-sig")

if ".super-admin-section" not in css_text:
    css_text += r'''

/* =========================================================
   SUPER ADMIN COMMAND CENTER
   ========================================================= */

.super-admin-section {
  position: relative;
}

.super-admin-section::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  border-radius: 20px;
  background: linear-gradient(
    135deg,
    rgba(59, 130, 246, 0.035),
    transparent 45%,
    rgba(168, 85, 247, 0.035)
  );
}

.super-admin-status {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  padding: 9px 14px;
  border: 1px solid rgba(34, 197, 94, 0.35);
  border-radius: 999px;
  color: #86efac;
  background: rgba(34, 197, 94, 0.08);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.08em;
}

.super-admin-status span {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #22c55e;
  box-shadow: 0 0 12px rgba(34, 197, 94, 0.8);
}

.super-admin-status.disabled {
  color: #fca5a5;
  border-color: rgba(239, 68, 68, 0.35);
  background: rgba(239, 68, 68, 0.08);
}

.super-admin-status.disabled span {
  background: #ef4444;
  box-shadow: 0 0 12px rgba(239, 68, 68, 0.7);
}

.super-admin-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}

.super-admin-card {
  min-height: 175px;
  padding: 20px;
  border: 1px solid rgba(148, 163, 184, 0.16);
  border-radius: 18px;
  background: rgba(15, 23, 42, 0.72);
  box-shadow: 0 14px 35px rgba(0, 0, 0, 0.18);
  transition: transform 0.2s ease, border-color 0.2s ease;
}

.super-admin-card:hover {
  transform: translateY(-2px);
  border-color: rgba(96, 165, 250, 0.42);
}

.super-admin-card.danger:hover {
  border-color: rgba(239, 68, 68, 0.55);
}

.super-admin-card.warning:hover {
  border-color: rgba(245, 158, 11, 0.55);
}

.super-admin-card-top {
  display: flex;
  align-items: flex-start;
  gap: 13px;
}

.super-admin-icon {
  width: 42px;
  height: 42px;
  flex: 0 0 42px;
  display: grid;
  place-items: center;
  border-radius: 12px;
  background: rgba(59, 130, 246, 0.12);
  font-size: 20px;
}

.super-admin-card h3 {
  margin: 2px 0 5px;
  font-size: 15px;
}

.super-admin-card p {
  margin: 0;
  color: #94a3b8;
  font-size: 12px;
  line-height: 1.55;
}

.admin-toggle.large {
  width: 52px;
  height: 28px;
  margin-top: 26px;
}

.admin-toggle.large span {
  width: 20px;
  height: 20px;
}

.admin-toggle.large.active span {
  transform: translateX(24px);
}

.admin-toggle.danger-active {
  background: rgba(239, 68, 68, 0.9);
}

.admin-toggle.warning-active {
  background: rgba(245, 158, 11, 0.9);
}

.super-admin-command-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 20px;
  margin-top: 16px;
  padding: 18px 20px;
  border: 1px solid rgba(148, 163, 184, 0.16);
  border-radius: 16px;
  background: rgba(15, 23, 42, 0.82);
}

.super-admin-last-action {
  display: flex;
  flex-direction: column;
  gap: 5px;
  min-width: 0;
}

.command-label {
  color: #64748b;
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.1em;
}

.super-admin-last-action strong {
  color: #e2e8f0;
  font-size: 13px;
}

.super-admin-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 9px;
}

@media (max-width: 1100px) {
  .super-admin-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 700px) {
  .super-admin-grid {
    grid-template-columns: 1fr;
  }

  .super-admin-command-bar {
    flex-direction: column;
    align-items: stretch;
  }

  .super-admin-actions {
    justify-content: flex-start;
  }
}
'''

    css.write_text(css_text, encoding="utf-8", newline="\n")

print("Super Admin Command Center installed successfully.")
