from pathlib import Path

path = Path(r"frontend/src/executive/ExecutiveDashboard.jsx")
text = path.read_text(encoding="utf-8")

lines = text.splitlines()

for i, line in enumerate(lines):
    if "Security Maturity Scorecard" in line and "ðŸ" in line:
        lines[i] = line.replace("ðŸ†", "").lstrip()

    if "Pause" in line and "â¸" in line:
        lines[i] = line.replace("â¸", "").lstrip()

path.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("Targeted Python cleanup completed.")
