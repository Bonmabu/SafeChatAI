from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

# Repeatedly reverse common UTF-8/Latin-1 mojibake corruption.
# Only apply it to lines that actually contain mojibake markers.
markers = (
    "Ãƒ", "Ã‚", "Ã¢", "â‚¬", "â€", "Â"
)

fixed = []
changed = 0

for line in text.splitlines():
    original = line

    if any(marker in line for marker in markers):
        for _ in range(4):
            try:
                candidate = line.encode("latin1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                break

            if candidate == line:
                break

            line = candidate

    if line != original:
        changed += 1

    fixed.append(line)

path.write_text("\n".join(fixed) + "\n", encoding="utf-8")

print(f"Repaired {changed} mojibake lines in main.py.")
