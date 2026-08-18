import { Link, useLocation, useNavigate } from "react-router-dom";

export default function CustomerNav() {
  const location = useLocation();
  const navigate = useNavigate();

  const linkStyle = (path) => ({
    color: location.pathname === path ? "#22d3ee" : "white",
    textDecoration: "none",
    padding: "10px 18px",
    borderRadius: 8,
    background:
      location.pathname === path ? "#1e293b" : "transparent",
    fontWeight: "bold"
  });

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("tenant_id");

    navigate("/login", { replace: true });
  };

  return (
    <div
      style={{
        display: "flex",
        gap: 15,
        padding: 15,
        marginBottom: 25,
        background: "#111827",
        borderRadius: 10,
        alignItems: "center"
      }}
    >
      <Link to="/customer" style={linkStyle("/customer")}>
        🛡️ Dashboard
      </Link>

      <Link
        to="/customer/analytics"
        style={linkStyle("/customer/analytics")}
      >
        📊 Analytics
      </Link>

      <Link
        to="/customer/timeline"
        style={linkStyle("/customer/timeline")}
      >
        📜 Timeline
      </Link>

      <button
        onClick={handleLogout}
        style={{
          marginLeft: "auto",
          padding: "10px 20px",
          borderRadius: 8,
          border: "1px solid #ef4444",
          background: "#0f172a",
          color: "#ef4444",
          fontWeight: "bold",
          cursor: "pointer"
        }}
      >
        Logout
      </button>
    </div>
  );
}