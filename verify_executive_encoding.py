from pathlib import Path

path = Path(r"frontend/src/executive/ExecutiveDashboard.jsx")
text = path.read_text(encoding="utf-8")

bad_markers = [
    "ðŸ", "â", "Â", "�"
]

found = []

for i, line in enumerate(text.splitlines(), 1):
    if any(marker in line for marker in bad_markers):
        found.append((i, line))

print(f"Potential mojibake lines: {len(found)}")

for line_no, line in found[:50]:
    print(f"{line_no}: {line}")

if not found:
    print("CLEAN: No common mojibake markers found.")
