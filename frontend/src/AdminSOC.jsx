import App from "./App";
import AdminUserMetrics from "./AdminUserMetrics";
import AdminUserDirectory from "./AdminUserDirectory";

export default function AdminSOC() {
  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        background:
          "radial-gradient(circle at top right, rgba(0,255,200,0.06), transparent 30%), #020617",
      }}
    >
      <section
        style={{
          position: "relative",
          overflow: "hidden",
          margin: "8px 8px 18px",
          padding: "28px 30px",
          borderRadius: 20,
          border: "1px solid rgba(0,255,200,0.14)",
          background:
            "linear-gradient(135deg, rgba(15,23,42,0.98), rgba(8,15,30,0.96))",
          boxShadow:
            "0 18px 50px rgba(0,0,0,0.28), inset 0 1px 0 rgba(255,255,255,0.03)",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: -60,
            right: -40,
            width: 180,
            height: 180,
            borderRadius: "50%",
            background: "rgba(0,255,200,0.08)",
            filter: "blur(20px)",
            pointerEvents: "none",
          }}
        />

        <div
          style={{
            position: "relative",
            zIndex: 1,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 20,
            flexWrap: "wrap",
          }}
        >
          <div>
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                marginBottom: 12,
                padding: "6px 10px",
                borderRadius: 999,
                border: "1px solid rgba(34,197,94,0.20)",
                background: "rgba(34,197,94,0.08)",
                color: "#86efac",
                fontSize: 11,
                fontWeight: 800,
                letterSpacing: "0.10em",
                textTransform: "uppercase",
              }}
            >
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: "#22c55e",
                  boxShadow: "0 0 10px rgba(34,197,94,0.8)",
                }}
              />
              Admin Security Operations
            </div>

            <h1
              style={{
                margin: 0,
                fontSize: "clamp(26px, 3.2vw, 42px)",
                lineHeight: 1.08,
                fontWeight: 850,
                letterSpacing: "-0.03em",
                color: "#f8fafc",
              }}
            >
              <span
                style={{
                  color: "#00ffc8",
                  marginRight: 10,
                }}
              >
                🛡️
              </span>
              SafeChat AI SOC Command Center
            </h1>

            <p
              style={{
                margin: "10px 0 0",
                maxWidth: 760,
                color: "#94a3b8",
                fontSize: 14,
                lineHeight: 1.6,
              }}
            >
              Enterprise identity, access, tenant governance and security
              operations in one control surface.
            </p>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "12px 14px",
              borderRadius: 14,
              border: "1px solid #1e293b",
              background: "rgba(15,23,42,0.72)",
              minWidth: 180,
            }}
          >
            <span
              style={{
                fontSize: 20,
              }}
            >
              ⚡
            </span>

            <div>
              <div
                style={{
                  color: "#64748b",
                  fontSize: 10,
                  fontWeight: 800,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                }}
              >
                Control Status
              </div>

              <div
                style={{
                  marginTop: 3,
                  color: "#22c55e",
                  fontSize: 13,
                  fontWeight: 800,
                }}
              >
                OPERATIONAL
              </div>
            </div>
          </div>
        </div>
      </section>

      <App />

      <AdminUserMetrics />

      <AdminUserDirectory />
    </div>
  );
}
