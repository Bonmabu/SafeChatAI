from pathlib import Path

path = Path(r".\frontend\src\AdminSOC.jsx")

text = path.read_text(encoding="utf-8-sig")

text = text.replace(
    'export default function AdminSOC() {\n',
    '''export default function AdminSOC() {

  const [superAdminMode, setSuperAdminMode] = useState(true);
  const [lockdownMode, setLockdownMode] = useState(false);
  const [autonomousAI, setAutonomousAI] = useState(true);
  const [maintenanceMode, setMaintenanceMode] = useState(false);
  const [lastAction, setLastAction] = useState("System ready");

  const runAdminAction = (action, callback) => {
    const confirmed = window.confirm(
      `Super Admin Action\\n\\n${action}\\n\\nContinue?`
    );

    if (!confirmed) return;

    callback();
    setLastAction(action);
  };

  const refreshAdminSOC = () => {
    window.location.reload();
  };

'''
)

path.write_text(text, encoding="utf-8", newline="\n")

print("AdminSOC.jsx Super Admin state repaired cleanly.")
