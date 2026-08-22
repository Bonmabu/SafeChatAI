import { useEffect, useState } from "react";
import axios from "axios";

const API =
  import.meta.env.VITE_API_BASE ||
  "http://127.0.0.1:8000";

export default function AdminUserMetrics() {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    let mounted = true;

    axios
      .get(`${API}/executive/users`)
      .then((res) => {
        if (mounted) {
          setUsers(res.data?.users || []);
        }
      })
      .catch((err) => {
        console.error("Admin user metrics error:", err);
      });

    return () => {
      mounted = false;
    };
  }, []);

  const newAccounts = users.filter((user) => {
    if (!user.created_at) return false;

    return (
      new Date(user.created_at).toDateString() ===
      new Date().toDateString()
    );
  }).length;

  const activeUsers = users.filter(
    (user) => user.active
  ).length;

  const cardStyle = {
    background: "#111827",
    border: "1px solid #1e293b",
    borderRadius: 12,
    padding: 18,
  };

  return (
    <section
      style={{
        marginBottom: 20,
      }}
    >
      <h2
        style={{
          color: "#00ffc8",
          marginBottom: 14,
        }}
      >
        User Management
      </h2>

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit,minmax(180px,1fr))",
          gap: 14,
        }}
      >
        <div style={cardStyle}>
          <div
            style={{
              color: "#94a3b8",
              fontSize: 13,
            }}
          >
            &#x1F465; Total Users
          </div>

          <div
            style={{
              fontSize: 28,
              fontWeight: 800,
              marginTop: 6,
            }}
          >
            {users.length}
          </div>
        </div>

        <div style={cardStyle}>
          <div
            style={{
              color: "#94a3b8",
              fontSize: 13,
            }}
          >
            &#x1F195; New Accounts
          </div>

          <div
            style={{
              fontSize: 28,
              fontWeight: 800,
              marginTop: 6,
            }}
          >
            {newAccounts}
          </div>
        </div>

        <div style={cardStyle}>
          <div
            style={{
              color: "#94a3b8",
              fontSize: 13,
            }}
          >
            &#x1F7E2; Active Users
          </div>

          <div
            style={{
              fontSize: 28,
              fontWeight: 800,
              marginTop: 6,
            }}
          >
            {activeUsers}
          </div>
        </div>
      </div>
    </section>
  );
}
