from pathlib import Path

path = Path(r"frontend/src/executive/ExecutiveDashboard.jsx")
lines = path.read_text(encoding="utf-8").splitlines()

# Known remaining mojibake lines
lines[1507] = "Security Maturity Scorecard"
lines[3287] = "Pause"

path.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("Replaced lines 1508 and 3288 directly.")
