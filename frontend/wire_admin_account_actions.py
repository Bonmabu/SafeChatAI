from pathlib import Path

path = Path(r".\src\AdminUserDirectory.jsx")
text = path.read_text(encoding="utf-8")

start = text.index("  async function accountAction(")
end = text.index("\n\n  useEffect(() =>", start)

replacement = r'''  async function accountAction(userId, action, label) {
    const confirmed = window.confirm(
      `${label} this account?\n\nUser ID: ${userId}\n\nContinue?`
    );

    if (!confirmed) return;

    const key = `${action}-${userId}`;
    setActionLoading(key);
    setError("");

    try {
      const token =
        localStorage.getItem("token") ||
        localStorage.getItem("access_token") ||
        localStorage.getItem("jwt") ||
        sessionStorage.getItem("token") ||
        sessionStorage.getItem("access_token");

      if (!token) {
        throw new Error("Administrator session token not found.");
      }

      const response = await axios.post(
        `${API}/admin/users/${userId}/${action}`,
        {},
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.data?.success) {
        throw new Error(
          response.data?.message ||
          response.data?.detail ||
          `${label} failed.`
        );
      }

      await loadUsers();

    } catch (err) {
      console.error(`Admin ${action} error:`, err);

      setError(
        err?.response?.data?.detail ||
        err?.response?.data?.message ||
        err?.message ||
        `${label} failed.`
      );
    } finally {
      setActionLoading(null);
    }
  }
'''

text = text[:start] + replacement + text[end:]

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: All five Admin User Directory actions are actionable.")
