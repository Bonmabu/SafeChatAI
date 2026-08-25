from pathlib import Path
import shutil

path = Path("main.py")
backup = Path("main.py.before_mojibake_repair")

shutil.copy2(path, backup)
print(f"Backup created: {backup}")

text = path.read_text(encoding="utf-8")
lines = text.splitlines()

markers = ("Ã", "Â", "â", "ƒ", "€", "™", "š", "œ")

changed = 0
fixed = []

for line in lines:
    original = line

    if any(marker in line for marker in markers):
        candidate = line

        for _ in range(3):
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

path.write_text("\n".join(fixed) + "\n", encoding="utf-8", newline="\n")

print(f"Repaired {changed} mojibake lines in main.py.")
