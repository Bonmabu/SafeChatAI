from pathlib import Path
import shutil
from datetime import datetime

path = Path("main.py")

backup = Path(
    f"main.py.before_fetchone_row_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
)
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

replacements = [
    (
        '    scans = cur.fetchone()[0]',
        '    row = cur.fetchone()\n    scans = row["COUNT(*)"] if row is not None else 0'
    ),
    (
        '    alerts = cur.fetchone()[0]',
        '    row = cur.fetchone()\n    alerts = row["COUNT(*)"] if row is not None else 0'
    ),
    (
        '    incidents = cur.fetchone()[0]',
        '    row = cur.fetchone()\n    incidents = row["COUNT(*)"] if row is not None else 0'
    ),
]

changed = 0

for old, new in replacements:
    while old in text:
        text = text.replace(old, new, 1)
        changed += 1

path.write_text(text, encoding="utf-8", newline="\n")

print(f"SUCCESS: repaired {changed} fetchone()[0] occurrences.")
print(f"Backup created: {backup.name}")
