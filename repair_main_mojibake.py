from pathlib import Path

path = Path(r".\main.py")
backup = Path(r".\main.py.before_mojibake_fix.bak")

text = path.read_text(encoding="utf-8")
backup.write_text(text, encoding="utf-8", newline="\n")

markers = ("Ã", "Â", "â", "ð", "ƒ", "‚", "™", "�")

def score(s):
    return sum(s.count(x) for x in markers)

def repair_line(line):
    current = line

    for _ in range(30):
        candidates = []

        for enc in ("latin1", "cp1252"):
            try:
                candidate = current.encode(enc).decode("utf-8")
                candidates.append(candidate)
            except (UnicodeEncodeError, UnicodeDecodeError):
                pass

        if not candidates:
            break

        best = min(candidates, key=score)

        if score(best) >= score(current):
            break

        current = best

    return current

lines = text.splitlines()
changed = 0

for i, line in enumerate(lines):
    fixed = repair_line(line)
    if fixed != line:
        lines[i] = fixed
        changed += 1
        print(f"FIXED LINE {i + 1}")

path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

print()
print(f"Changed lines: {changed}")
print("Backup:", backup)
print("DONE")
