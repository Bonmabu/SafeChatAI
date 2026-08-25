from pathlib import Path

files = [
    Path("src/App.jsx"),
    Path("src/Login.jsx"),
    Path("src/executive/ExecutiveDashboard.jsx"),
]

markers = (
    "Ã", "Â", "â", "ð", "Å", "�"
)

def repair_line(line):
    current = line

    for _ in range(4):
        if not any(marker in current for marker in markers):
            break

        try:
            repaired = current.encode("cp1252").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            break

        if repaired == current:
            break

        current = repaired

    return current

for path in files:
    if not path.exists():
        print(f"NOT FOUND: {path}")
        continue

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    changed = 0
    output = []

    for line in lines:
        new_line = repair_line(line)

        if new_line != line:
            changed += 1

        output.append(new_line)

    path.write_text("".join(output), encoding="utf-8", newline="\n")

    print(f"{path}: repaired {changed} line(s)")

print("Mojibake repair completed.")
