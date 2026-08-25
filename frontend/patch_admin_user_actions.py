from pathlib import Path

path = Path(r"C:\Users\PC\SafeChatAI\frontend\src\AdminUserDirectory.jsx")
text = path.read_text(encoding="utf-8")

text = text.replace(
'''  const [error, setError] = useState("");
''',
'''  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState(null);
'''
)

marker = '''  useEffect(() => {
    loadUsers();
  }, []);
'''

patch = r'''
  async function accountAction(userId, action, label) {
    const confirmed = window.confirm(
      `${label} this account?\\n\\nUser ID: ${userId}\\n\\nContinue?`
    );

    if (!confirmed) return;

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
        setError("Administrator session token not found. Please sign in again.");
        return;
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
        throw new Error(res.data?.message || `${label} failed.`);
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

if "async function accountAction(" not in text:
    if marker not in text:
        raise SystemExit("Insertion marker not found. No changes made.")
    text = text.replace(marker, patch + marker)

old = '''                  "MFA",
                  "Created",
'''

new = '''                  "MFA",
                  "Created",
                  "Actions",
'''

if old in text:
    text = text.replace(old, new, 1)

old_row = '''                    <td
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
'''

new_row = old_row + '''
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
                          disabled={actionLoading === `password-reset-${user.id}`}
                          onClick={() =>
                            accountAction(
                              user.id,
                              "password-reset",
                              "Generate password reset"
                            )
                          }
                          style={actionButtonStyle("#2563eb")}
                        >
                          {actionLoading === `password-reset-${user.id}`
                            ? "Working..."
                            : "Reset Password"}
                        </button>

                        {status === "suspended" ? (
                          <button
                            type="button"
                            disabled={actionLoading === `activate-${user.id}`}
                            onClick={() =>
                              accountAction(user.id, "activate", "Activate")
                            }
                            style={actionButtonStyle("#16a34a")}
                          >
                            {actionLoading === `activate-${user.id}`
                              ? "Working..."
                              : "Activate"}
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={actionLoading === `suspend-${user.id}`}
                            onClick={() =>
                              accountAction(user.id, "suspend", "Suspend")
                            }
                            style={actionButtonStyle("#d97706")}
                          >
                            {actionLoading === `suspend-${user.id}`
                              ? "Working..."
                              : "Suspend"}
                          </button>
                        )}

                        {status === "locked" ? (
                          <button
                            type="button"
                            disabled={actionLoading === `unlock-${user.id}`}
                            onClick={() =>
                              accountAction(user.id, "unlock", "Unlock")
                            }
                            style={actionButtonStyle("#16a34a")}
                          >
                            {actionLoading === `unlock-${user.id}`
                              ? "Working..."
                              : "Unlock"}
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={actionLoading === `lock-${user.id}`}
                            onClick={() =>
                              accountAction(user.id, "lock", "Lock")
                            }
                            style={actionButtonStyle("#dc2626")}
                          >
                            {actionLoading === `lock-${user.id}`
                              ? "Working..."
                              : "Lock"}
                          </button>
                        )}
                      </div>
                    </td>
'''

if old_row not in text:
    raise SystemExit("User table row marker not found. No changes made.")

text = text.replace(old_row, new_row, 1)

helper_marker = '''export default function AdminUserDirectory() {
'''

helper = '''const actionButtonStyle = (background) => ({
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

if "const actionButtonStyle =" not in text:
    text = text.replace(helper_marker, helper + helper_marker, 1)

path.write_text(text, encoding="utf-8", newline="`n")

print("Admin User Directory account actions installed.")

