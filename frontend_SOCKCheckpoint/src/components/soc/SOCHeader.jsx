export default function SOCHeader({ onLogout }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "20px",
        width: "100%"
      }}
    >
      <h1
        style={{
          color: "#ffffff",
          margin: 0
        }}
      >
        🛡️ SafeChat AI SOC Command Center
      </h1>

      <button
        onClick={onLogout}
        style={{
          background: "#ef4444",
          color: "white",
          border: "none",
          padding: "10px 16px",
          borderRadius: 8,
          cursor: "pointer",
          fontWeight: "bold"
        }}
      >
        Logout
      </button>
    </div>
  );
}