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
      const res = await axios.get(
        `${API}/executive/users`
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
      <h2 style={{ color: "#00ffc8", marginBottom: 20 }}>
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
              minWidth: 900,
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
                ].map((heading) => (
                  <th
                    key={heading}
                    style={{
                      textAlign: "left",
                      padding: 12,
                      borderBottom:
                        "1px solid #334155",
                      color: "#94a3b8",
                    }}
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {users.map((user) => {
                const isActive =
                  user.active === true ||
                  user.is_active === true ||
                  String(user.status || "").toLowerCase() ===
                    "active";

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
                        color: isActive
                          ? "#22c55e"
                          : "#94a3b8",
                        fontWeight: 700,
                      }}
                    >
                      ●{" "}
                      {isActive
                        ? "Active"
                        : "Inactive"}
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
