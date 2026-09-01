import { useEffect, useState } from "react";
import axios from "axios";

const API =
  import.meta.env.VITE_API_BASE ||
  "http://127.0.0.1:8000";

export default function AdminUserDirectory() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  async function loadUsers() {
    try {
      const token =
        localStorage.getItem("token") ||
        localStorage.getItem("access_token");

      const res = await axios.get(
        `${API}/executive/users`,
        {
          headers: token
            ? {
                Authorization: `Bearer ${token}`,
              }
            : {},
        }
      );

      setUsers(res.data?.users || []);
    } catch (error) {
      console.error("Admin user directory error:", error);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  const totalUsers = users.length;

  const today = new Date().toDateString();

  const newAccounts = users.filter((user) => {
    const created = user.created_at
      ? new Date(user.created_at)
      : null;

    return created && created.toDateString() === today;
  }).length;

  const activeUsers = users.filter((user) => {
    if (typeof user.active === "boolean") {
      return user.active;
    }

    if (typeof user.is_active === "boolean") {
      return user.is_active;
    }

    return String(user.status || "").toLowerCase() === "active";
  }).length;

  async function resetPassword(userId) {
    if (!window.confirm("Reset this user's password?")) {
      return;
    }

    try {
      const token =
        localStorage.getItem("token") ||
        localStorage.getItem("access_token");

      const res = await axios.post(
        `${API}/admin/users/${userId}/password-reset`,
        {},
        {
          headers: {
            Authorization: "Bearer " + token,
          },
        }
      );

      alert(
        res.data?.message ||
        "Password reset initiated successfully."
      );
    } catch (error) {
      console.error("Password reset error:", error);

      alert(
        error.response?.data?.detail ||
        "Unable to reset password."
      );
    }
  }

  async function changeUserStatus(userId, status) {
    if (
      status === "suspended" &&
      !window.confirm("Suspend this user?")
    ) {
      return;
    }

    if (
      status === "blocked" &&
      !window.confirm("Lock/block this user?")
    ) {
      return;
    }

    if (
      status === "active" &&
      !window.confirm("Activate this user?")
    ) {
      return;
    }

    try {
      const token =
        localStorage.getItem("token") ||
        localStorage.getItem("access_token");

      await axios.patch(
        `${API}/admin/users/${userId}/status`,
        null,
        {
          params: {
            status,
          },
          headers: {
            Authorization: "Bearer " + token,
          },
        }
      );

      await loadUsers();
    } catch (error) {
      console.error("User status error:", error);

      alert(
        error.response?.data?.detail ||
        "Unable to change user status."
      );
    }
  }

  async function forceLogout(userId) {
    if (!window.confirm("Force this user to log out?")) {
      return;
    }

    try {
      const token =
        localStorage.getItem("token") ||
        localStorage.getItem("access_token");

      await axios.post(
        `${API}/admin/users/${userId}/force-logout`,
        {},
        {
          headers: {
            Authorization: "Bearer " + token,
          },
        }
      );

      alert("User sessions have been invalidated.");

      await loadUsers();
    } catch (error) {
      console.error("Force logout error:", error);

      alert(
        error.response?.data?.detail ||
        "Unable to force logout."
      );
    }
  }

  function getUserStatus(user) {
    const status = String(
      user.status || ""
    ).toLowerCase();

    if (status === "blocked") {
      return "blocked";
    }

    if (status === "suspended") {
      return "suspended";
    }

    if (
      user.is_active === false ||
      user.active === false
    ) {
      return "inactive";
    }

    return "active";
  }

  return (
    <div
      style={{
        marginTop: 20,
        padding: 24,
        background: "#0f172a",
        border: "1px solid #1e293b",
        borderRadius: 14,
        color: "#fff",
      }}
    >
      <h2
        style={{
          color: "#00ffc8",
          marginBottom: 20,
        }}
      >
        Enterprise User Directory
      </h2>

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit,minmax(180px,1fr))",
          gap: 14,
          marginBottom: 24,
        }}
      >
        <div
          style={{
            padding: 18,
            background: "#111827",
            borderRadius: 12,
          }}
        >
          <div style={{ color: "#94a3b8" }}>
            Total Users
          </div>

          <h2 style={{ margin: "8px 0 0" }}>
            {totalUsers}
          </h2>
        </div>

        <div
          style={{
            padding: 18,
            background: "#111827",
            borderRadius: 12,
          }}
        >
          <div style={{ color: "#94a3b8" }}>
            New Accounts
          </div>

          <h2 style={{ margin: "8px 0 0" }}>
            {newAccounts}
          </h2>
        </div>

        <div
          style={{
            padding: 18,
            background: "#111827",
            borderRadius: 12,
          }}
        >
          <div style={{ color: "#94a3b8" }}>
            Active Users
          </div>

          <h2 style={{ margin: "8px 0 0" }}>
            {activeUsers}
          </h2>
        </div>
      </div>

      <p style={{ color: "#94a3b8" }}>
        {loading
          ? "Loading users..."
          : `${totalUsers} registered users`}
      </p>

      {!loading && (
        <div style={{ overflowX: "auto" }}>
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              minWidth: 1250,
            }}
          >
            <thead>
              <tr>
                {[
                  "ID",
                  "Full Name",
                  "Username",
                  "Email",
                  "Role",
                  "Tenant ID",
                  "Created",
                  "Status",
                  "Actions",
                ].map((heading) => (
                  <th
                    key={heading}
                    style={{
                      textAlign: "left",
                      padding: 12,
                      borderBottom:
                        "1px solid #334155",
                      color: "#94a3b8",
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
                const status = getUserStatus(user);

                const isActive =
                  status === "active";

                const isBlocked =
                  status === "blocked";

                const isSuspended =
                  status === "suspended";

                return (
                  <tr key={user.id}>
                    <td style={{ padding: 12 }}>
                      {user.id}
                    </td>

                    <td style={{ padding: 12 }}>
                      <strong>
                        {user.full_name || "—"}
                      </strong>
                    </td>

                    <td style={{ padding: 12 }}>
                      {user.username || "—"}
                    </td>

                    <td style={{ padding: 12 }}>
                      {user.email || "—"}
                    </td>

                    <td style={{ padding: 12 }}>
                      <strong>
                        {user.role || "—"}
                      </strong>
                    </td>

                    <td style={{ padding: 12 }}>
                      {user.tenant_id || "—"}
                    </td>

                    <td style={{ padding: 12 }}>
                      {user.created_at
                        ? new Date(
                            user.created_at
                          ).toLocaleString()
                        : "—"}
                    </td>

                    <td
                      style={{
                        padding: 12,
                        fontWeight: 700,
                        whiteSpace: "nowrap",
                        color:
                          isBlocked
                            ? "#ef4444"
                            : isSuspended
                            ? "#f59e0b"
                            : isActive
                            ? "#22c55e"
                            : "#94a3b8",
                      }}
                    >
                      ●{" "}
                      {isBlocked
                        ? "Blocked"
                        : isSuspended
                        ? "Suspended"
                        : isActive
                        ? "Active"
                        : "Inactive"}
                    </td>

                    <td style={{ padding: 12 }}>
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: 8,
                          minWidth: 360,
                        }}
                      >
                        <button
                          type="button"
                          onClick={() =>
                            resetPassword(user.id)
                          }
                          style={{
                            padding: "7px 10px",
                            borderRadius: 7,
                            border:
                              "1px solid #475569",
                            background: "#1e293b",
                            color: "#fff",
                            cursor: "pointer",
                            fontWeight: 600,
                          }}
                        >
                          🔑 Reset Password
                        </button>

                        {isActive && (
                          <button
                            type="button"
                            onClick={() =>
                              changeUserStatus(
                                user.id,
                                "suspended"
                              )
                            }
                            style={{
                              padding: "7px 10px",
                              borderRadius: 7,
                              border:
                                "1px solid #92400e",
                              background: "#451a03",
                              color: "#fbbf24",
                              cursor: "pointer",
                              fontWeight: 600,
                            }}
                          >
                            ⏸ Suspend
                          </button>
                        )}

                        {(isSuspended ||
                          isBlocked) && (
                          <button
                            type="button"
                            onClick={() =>
                              changeUserStatus(
                                user.id,
                                "active"
                              )
                            }
                            style={{
                              padding: "7px 10px",
                              borderRadius: 7,
                              border:
                                "1px solid #166534",
                              background: "#052e16",
                              color: "#4ade80",
                              cursor: "pointer",
                              fontWeight: 600,
                            }}
                          >
                            🟢 Activate
                          </button>
                        )}

                        {!isBlocked && (
                          <button
                            type="button"
                            onClick={() =>
                              changeUserStatus(
                                user.id,
                                "blocked"
                              )
                            }
                            style={{
                              padding: "7px 10px",
                              borderRadius: 7,
                              border:
                                "1px solid #991b1b",
                              background: "#450a0a",
                              color: "#f87171",
                              cursor: "pointer",
                              fontWeight: 600,
                            }}
                          >
                            🔒 Lock
                          </button>
                        )}

                        <button
                          type="button"
                          onClick={() =>
                            forceLogout(user.id)
                          }
                          style={{
                            padding: "7px 10px",
                            borderRadius: 7,
                            border:
                              "1px solid #475569",
                            background: "#0f172a",
                            color: "#cbd5e1",
                            cursor: "pointer",
                            fontWeight: 600,
                          }}
                        >
                          🚪 Force Logout
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

