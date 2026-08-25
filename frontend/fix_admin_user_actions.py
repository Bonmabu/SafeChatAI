from pathlib import Path

path = Path(".\src\AdminUserDirectory.jsx")
text = path.read_text(encoding="utf-8")

# Add state
if "actionLoading" not in text:
    text = text.replace(
        '  const [error, setError] = useState("");',
        '  const [error, setError] = useState("");\n  const [actionLoading, setActionLoading] = useState(null);',
        1
    )

# Add action handler immediately before return
if "async function accountAction" not in text:
    marker = "  return ("
    pos = text.find(marker)
    if pos < 0:
        raise SystemExit("RETURN MARKER NOT FOUND - FILE NOT CHANGED.")

    fn = r'''
  async function accountAction(userId, action, label) {
    if (!window.confirm(`${label} this account?\n\nUser ID: ${userId}\n\nContinue?`)) {
      return;
    }

    setActionLoading(`${action}-${userId}`);
    setError("");

    try {
      const token =
        localStorage.getItem("token") ||
        localStorage.getItem("access_token") ||
        localStorage.getItem("jwt") ||
        sessionStorage.getItem("token") ||
        sessionStorage.getItem("access_token");

      if (!token) {
        throw new Error("Administrator session token not found. Please sign in again.");
      }

      const response = await axios.post(
        `${API}/admin/users/${userId}/${action}`,
        {},
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.data?.success) {
        throw new Error(response.data?.message || `${label} failed.`);
      }

      await loadUsers();
    } catch (error) {
      console.error(`Admin ${action} error:`, error);
      setError(
        error?.response?.data?.detail ||
        error?.response?.data?.message ||
        error?.message ||
        `${label} failed.`
      );
    } finally {
      setActionLoading(null);
    }
  }

'''
    text = text[:pos] + fn + text[pos:]

# Add Actions heading
if '"Actions"' not in text:
    text = text.replace(
        '                  "Created",',
        '                  "Created",\n                  "Actions",',
        1
    )

# Add action cell after Created cell
if 'accountAction(user.id, "password-reset"' not in text:
    marker = '''                    <td
                      style={{
                        padding: "14px 12px",
                        color: "#94a3b8",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {user.created_at
                        ? new Date(user.created_at).toLocaleString()
                        : "—"}
                    </td>'''

    if marker not in text:
        raise SystemExit("CREATED CELL MARKER NOT FOUND - FILE NOT CHANGED.")

    cell = r'''
                    <td style={{ padding: "14px 12px" }}>
                      <div style={{
                        display: "flex",
                        gap: 7,
                        flexWrap: "wrap",
                        minWidth: 430,
                      }}>

                        <button
                          type="button"
                          disabled={actionLoading === `password-reset-${user.id}`}
                          onClick={() => accountAction(user.id, "password-reset", "Generate password reset")}
                          style={actionButtonStyle("#2563eb")}
                        >
                          {actionLoading === `password-reset-${user.id}` ? "Working..." : "Reset Password"}
                        </button>

                        {status === "suspended" ? (
                          <button
                            type="button"
                            disabled={actionLoading === `activate-${user.id}`}
                            onClick={() => accountAction(user.id, "activate", "Activate")}
                            style={actionButtonStyle("#16a34a")}
                          >
                            {actionLoading === `activate-${user.id}` ? "Working..." : "Activate"}
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={actionLoading === `suspend-${user.id}`}
                            onClick={() => accountAction(user.id, "suspend", "Suspend")}
                            style={actionButtonStyle("#d97706")}
                          >
                            {actionLoading === `suspend-${user.id}` ? "Working..." : "Suspend"}
                          </button>
                        )}

                        {status === "locked" ? (
                          <button
                            type="button"
                            disabled={actionLoading === `unlock-${user.id}`}
                            onClick={() => accountAction(user.id, "unlock", "Unlock")}
                            style={actionButtonStyle("#16a34a")}
                          >
                            {actionLoading === `unlock-${user.id}` ? "Working..." : "Unlock"}
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={actionLoading === `lock-${user.id}`}
                            onClick={() => accountAction(user.id, "lock", "Lock")}
                            style={actionButtonStyle("#dc2626")}
                          >
                            {actionLoading === `lock-${user.id}` ? "Working..." : "Lock"}
                          </button>
                        )}

                      </div>
                    </td>'''

    text = text.replace(marker, marker + cell, 1)

# Add button style
if "function actionButtonStyle" not in text and "const actionButtonStyle" not in text:
    marker = "export default function AdminUserDirectory()"
    pos = text.find(marker)

    if pos < 0:
        raise SystemExit("COMPONENT MARKER NOT FOUND - FILE NOT CHANGED.")

    style = '''const actionButtonStyle = (background) => ({
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

'''
    text = text[:pos] + style + text[pos:]

path.write_text(text, encoding="utf-8", newline="\n")
print("SUCCESS: ADMIN USER ACCOUNT ACTIONS INSTALLED.")
