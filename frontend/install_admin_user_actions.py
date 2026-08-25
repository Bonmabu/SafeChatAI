from pathlib import Path

path = Path(r".\src\AdminUserDirectory.jsx")
text = path.read_text(encoding="utf-8")

# 1. Add action loading state
if "const [actionLoading, setActionLoading]" not in text:
    text = text.replace(
        '  const [error, setError] = useState("");',
        '  const [error, setError] = useState("");\n  const [actionLoading, setActionLoading] = useState(null);',
        1
    )

# 2. Add shared button style before component
if "const actionButtonStyle =" not in text:
    text = text.replace(
        'export default function AdminUserDirectory() {',
        '''const actionButtonStyle = (background) => ({
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

export default function AdminUserDirectory() {''',
        1
    )

# 3. Add account action function immediately before useEffect
if "async function accountAction(" not in text:
    marker = '  useEffect(() => {'
    position = text.find(marker)

    if position == -1:
        raise SystemExit("useEffect marker not found. No changes made.")

    action_function = r'''
  async function accountAction(userId, action, label) {
    const confirmed = window.confirm(
      `${label} this account?\n\nUser ID: ${userId}\n\nContinue?`
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
    text = text[:position] + action_function + text[position:]

# 4. Add Actions heading
if '"Actions",' not in text:
    text = text.replace(
        '                  "Created",\n                ].map',
        '                  "Created",\n                  "Actions",\n                ].map',
        1
    )

# 5. Add action buttons after Created cell
if 'accountAction(user.id, "password-reset"' not in text:
    created_cell = '''                    <td
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

    if created_cell not in text:
        raise SystemExit("Created table cell not found. No changes made.")

    action_cell = created_cell + r'''
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
                    </td>'''

    text = text.replace(created_cell, action_cell, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("ADMIN USER ACCOUNT ACTIONS INSTALLED.")
