import { useLocation, useNavigate } from "react-router-dom";

export default function CustomerNav() {
  const location = useLocation();
  const navigate = useNavigate();

  const linkStyle = (path) => ({
    color: location.pathname === path ? "#22d3ee" : "white",
    textDecoration: "none",
    fontWeight: 600,
    padding: "8px 12px",
    borderRadius: 8,
    background:
      location.pathname === path
        ? "rgba(34,211,238,0.10)"
        : "transparent",
  });

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        marginBottom: 20,
        padding: "10px 14px",
        background: "#0f172a",
        border: "1px solid #1e293b",
        borderRadius: 10,
      }}
    >
      <button
        type="button"
        onClick={() => navigate("/dashboard/customer")}
        style={{
          ...linkStyle("/dashboard/customer"),
          border: "none",
          cursor: "pointer",
          background:
            location.pathname === "/dashboard/customer"
              ? "rgba(34,211,238,0.10)"
              : "transparent",
        }}
      >
        🛡️ Dashboard
      </button>

      <button
        type="button"
        onClick={() => navigate("/dashboard/customer/analytics")}
        style={{
          ...linkStyle("/dashboard/customer/analytics"),
          border: "none",
          cursor: "pointer",
          background:
            location.pathname === "/dashboard/customer/analytics"
              ? "rgba(34,211,238,0.10)"
              : "transparent",
        }}
      >
        📊 Analytics
      </button>

      <button
        type="button"
        onClick={() => navigate("/dashboard/customer/timeline")}
        style={{
          ...linkStyle("/dashboard/customer/timeline"),
          border: "none",
          cursor: "pointer",
          background:
            location.pathname === "/dashboard/customer/timeline"
              ? "rgba(34,211,238,0.10)"
              : "transparent",
        }}
      >
        📜 Timeline
      </button>
    </div>
  );
}
