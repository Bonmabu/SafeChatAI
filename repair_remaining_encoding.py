from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

lines = text.splitlines()
changed = 0

# These remaining strings have an extra/mixed mojibake layer.
# Repair only lines that actually contain the characteristic mojibake markers.
markers = ("Ã", "Â", "â", "ƒ", "€", "™", "š", "œ")

fixed = []

for line in lines:
    original = line

    if any(marker in line for marker in markers):
        candidate = line

        # Try progressively deeper repair.
        for _ in range(6):
            try:
                repaired = candidate.encode("cp1252").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                break

            if repaired == candidate:
                break

            candidate = repaired

        line = candidate

    if line != original:
        changed += 1

    fixed.append(line)

path.write_text(
    "\n".join(fixed) + "\n",
    encoding="utf-8",
    newline="\n"
)

print(f"Additional mojibake repairs: {changed}")
