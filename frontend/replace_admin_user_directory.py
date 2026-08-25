from pathlib import Path

path = Path(r".\src\AdminUserDirectory.jsx")

text = r'''import { useEffect, useState } from "react";
import axios from "axios";

const API =
  import.meta.env.VITE_API_BASE ||
  "http://127.0.0.1:8000";

const actionButtonStyle = (background) => ({
  padding: "7px 10px",
  borderRadius: 7,
  border: "1px solid rgba(255,255,255,0.12)",
  background,
  color: "#fff",
  cursor: "pointer",
  fontSize: 11,
  fontWeight: 700,
  whiteSpace: "nowrap",
});

export default function AdminUserDirectory() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState(null);

  async function getToken() {
    return (
      localStorage.getItem("token") ||
      localStorage.getItem("access_token") ||
      localStorage.getItem("jwt") ||
      sessionStorage.getItem("token") ||
      sessionStorage.getItem("access_token")
    );
  }

  async function loadUsers() {
    setLoading(true);
    setError("");

    try {
      const token = await getToken();

      if (!token) {
        setError("Administrator session token not found. Please sign in again.");
        setUsers([]);
        return;
      }

      const res = await axios.get(`${API}/executive/users`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      setUsers(
        Array.isArray(res.data?.users)
          ? res.data.users
          : []
      );
    } catch (err) {
      console.error("Admin user directory error:", err);

      const status = err?.response?.status;

      if (status === 401) {
        setError("Administrator session expired or invalid. Please sign in again.");
      } else if (status === 403) {
        setError("Administrator privileges required.");
      } else {
        setError(
          err?.response?.data?.detail ||
          "Unable to load enterprise users."
        );
      }

      setUsers([]);
    } finally {
      setLoading(false);
    }
  }

  async function accountAction(userId, action, label) {
    const confirmed = window.confirm(
      `${label} this account?\n\nUser ID: ${userId}\n\nContinue?`
    );

    if (!confirmed) return;

    setActionLoading(`${action}-${userId}`);
    setError("");

    try {
      const token = await getToken();

      if (!token) {
        throw new Error(
          "Administrator session token not found. Please sign in again."
        );
      }

      const res = await axios.post(
        `${API}/admin/users/${userId}/${action}`,
        {},
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!res.data?.success) {
        throw new Error(
          res.data?.message || `${label} failed.`
        );
      }

      await loadUsers();
    } catch (err) {
      console.error(`Admin ${action} error:`, err);

      setError(
        err?.response?.data?.detail ||
        err?.response?.data?.message ||
        err?.message ||
        `${label} failed.`
      );
    } finally {
      setActionLoading(null);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  return (
    <section
      style={{
        marginTop: 24,
        padding: 24,
        background: "linear-gradient(180deg, #0f172a 0%, #0b1220 100%)",
        border: "1px solid #1e293b",
        borderRadius: 16,
        color: "#fff",
        boxShadow: "0 12px 35px rgba(0,0,0,0.18)",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 16,
          marginBottom: 20,
          flexWrap: "wrap",
        }}
      >
        <div>
          <h2
            style={{
              color: "#f8fafc",
              margin: 0,
              fontSize: 22,
              fontWeight: 700,
            }}
          >
            👥 Enterprise User Administration
          </h2>

          <div
            style={{
              marginTop: 6,
              color: "#64748b",
              fontSize: 13,
            }}
          >
            Account lifecycle, access, security and session management
          </div>
        </div>

        <button
          type="button"
          onClick={loadUsers}
          style={{
            padding: "9px 14px",
            borderRadius: 8,
            border: "1px solid #334155",
            background: "#111827",
            color: "#e2e8f0",
            cursor: "pointer",
            fontWeight: 600,
          }}
        >
          Refresh
        </button>
      </div>

      {error && (
        <div
          style={{
            marginBottom: 16,
            padding: 14,
            borderRadius: 10,
            background: "rgba(239,68,68,0.10)",
            border: "1px solid rgba(239,68,68,0.30)",
            color: "#fca5a5",
            fontSize: 14,
          }}
        >
          {error}
        </div>
      )}

      {loading ? (
        <div
          style={{
            color: "#94a3b8",
            padding: 40,
            textAlign: "center",
          }}
        >
          Loading enterprise users...
        </div>
      ) : users.length === 0 ? (
        <div
          style={{
            color: "#94a3b8",
            padding: 40,
            textAlign: "center",
            background: "#0b1220",
            borderRadius: 12,
            border: "1px solid #1e293b",
          }}
        >
          {error ? "Users could not be loaded." : "No registered users found."}
        </div>
      ) : (
        <div
          style={{
            overflowX: "auto",
            border: "1px solid #1e293b",
            borderRadius: 12,
            background: "#0b1220",
          }}
        >
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              minWidth: 1550,
            }}
          >
            <thead>
              <tr
                style={{
                  background: "#111827",
                  borderBottom: "1px solid #334155",
                }}
              >
                {[
                  "ID",
                  "User",
                  "Email",
                  "Role",
                  "Tenant",
                  "Status",
                  "MFA",
                  "Created",
                  "Actions",
                ].map((heading) => (
                  <th
                    key={heading}
                    style={{
                      padding: "13px 12px",
                      color: "#94a3b8",
                      fontSize: 12,
                      fontWeight: 700,
                      textAlign: "left",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {users.map((user) => {
                const status = String(
                  user.status || ""
                ).toLowerCase();

                const isActive =
                  user.active === true ||
                  user.is_active === true ||
                  status === "active" ||
                  (!user.status &&
                    user.is_active !== false &&
                    user.active !== false);

                const mfa =
                  user.mfa_enabled === true ||
                  user.mfa === true;

                const isSuspended = status === "suspended";
                const isLocked = status === "locked";

                return (
                  <tr
                    key={user.id}
                    style={{
                      borderBottom: "1px solid #1e293b",
                    }}
                  >
                    <td style={{ padding: "14px 12px", color: "#cbd5e1" }}>
                      {user.id}
                    </td>

                    <td style={{ padding: "14px 12px" }}>
                      <div style={{ color: "#f8fafc", fontWeight: 700 }}>
                        {user.full_name || user.username || "—"}
                      </div>
                      <div
                        style={{
                          color: "#38bdf8",
                          fontSize: 12,
                          marginTop: 3,
                        }}
                      >
                        @{user.username || "—"}
                      </div>
                    </td>

                    <td style={{ padding: "14px 12px", color: "#cbd5e1" }}>
                      {user.email || "—"}
                    </td>

                    <td style={{ padding: "14px 12px" }}>
                      <span
                        style={{
                          padding: "5px 9px",
                          borderRadius: 999,
                          background:
                            user.role === "customer"
                              ? "rgba(56,189,248,0.10)"
                              : "rgba(168,85,247,0.10)",
                          color:
                            user.role === "customer"
                              ? "#38bdf8"
                              : "#c084fc",
                          fontSize: 12,
                          fontWeight: 700,
                        }}
                      >
                        {user.role || "—"}
                      </span>
                    </td>

                    <td
                      style={{
                        padding: "14px 12px",
                        color: "#cbd5e1",
                      }}
                    >
                      {user.tenant_id || "—"}
                    </td>

                    <td style={{ padding: "14px 12px" }}>
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          color: isSuspended
                            ? "#f59e0b"
                            : isLocked
                              ? "#ef4444"
                              : isActive
                                ? "#22c55e"
                                : "#94a3b8",
                          fontWeight: 700,
                          fontSize: 13,
                        }}
                      >
                        <span
                          style={{
                            width: 7,
                            height: 7,
                            borderRadius: "50%",
                            background: isSuspended
                              ? "#f59e0b"
                              : isLocked
                                ? "#ef4444"
                                : isActive
                                  ? "#22c55e"
                                  : "#64748b",
                          }}
                        />
                        {isSuspended
                          ? "Suspended"
                          : isLocked
                            ? "Locked"
                            : isActive
                              ? "Active"
                              : "Inactive"}
                      </span>
                    </td>

                    <td style={{ padding: "14px 12px" }}>
                      <span
                        style={{
                          color: mfa ? "#22c55e" : "#f59e0b",
                          fontWeight: 700,
                          fontSize: 12,
                        }}
                      >
                        {mfa ? "ENABLED" : "NOT SET"}
                      </span>
                    </td>

                    <td
                      style={{
                        padding: "14px 12px",
                        color: "#94a3b8",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {user.created_at
                        ? new Date(user.created_at).toLocaleString()
                        : "—"}
                    </td>

                    <td style={{ padding: "14px 12px" }}>
                      <div
                        style={{
                          display: "flex",
                          gap: 7,
                          flexWrap: "wrap",
                          minWidth: 430,
                        }}
                      >
                        <button
                          type="button"
                          disabled={
                            actionLoading ===
                            `password-reset-${user.id}`
                          }
                          onClick={() =>
                            accountAction(
                              user.id,
                              "password-reset",
                              "Generate password reset"
                            )
                          }
                          style={actionButtonStyle("#2563eb")}
                        >
                          {actionLoading ===
                          `password-reset-${user.id}`
                            ? "Working..."
                            : "Reset Password"}
                        </button>

                        {isSuspended ? (
                          <button
                            type="button"
                            disabled={
                              actionLoading ===
                              `activate-${user.id}`
                            }
                            onClick={() =>
                              accountAction(
                                user.id,
                                "activate",
                                "Activate"
                              )
                            }
                            style={actionButtonStyle("#16a34a")}
                          >
                            {actionLoading ===
                            `activate-${user.id}`
                              ? "Working..."
                              : "Activate"}
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={
                              actionLoading ===
                              `suspend-${user.id}`
                            }
                            onClick={() =>
                              accountAction(
                                user.id,
                                "suspend",
                                "Suspend"
                              )
                            }
                            style={actionButtonStyle("#d97706")}
                          >
                            {actionLoading ===
                            `suspend-${user.id}`
                              ? "Working..."
                              : "Suspend"}
                          </button>
                        )}

                        {isLocked ? (
                          <button
                            type="button"
                            disabled={
                              actionLoading ===
                              `unlock-${user.id}`
                            }
                            onClick={() =>
                              accountAction(
                                user.id,
                                "unlock",
                                "Unlock"
                              )
                            }
                            style={actionButtonStyle("#16a34a")}
                          >
                            {actionLoading ===
                            `unlock-${user.id}`
                              ? "Working..."
                              : "Unlock"}
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={
                              actionLoading ===
                              `lock-${user.id}`
                            }
                            onClick={() =>
                              accountAction(
                                user.id,
                                "lock",
                                "Lock"
                              )
                            }
                            style={actionButtonStyle("#dc2626")}
                          >
                            {actionLoading ===
                            `lock-${user.id}`
                              ? "Working..."
                              : "Lock"}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
'''

path.write_text(text, encoding="utf-8", newline="\n")
print("SUCCESS: AdminUserDirectory.jsx replaced with account-management version.")
