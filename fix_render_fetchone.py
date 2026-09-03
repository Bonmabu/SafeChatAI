from pathlib import Path
import shutil
from datetime import datetime

path = Path("main.py")

backup = Path(
    f"main.py.before_render_fetchone_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
)
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

old = """    active_threats = cursor.fetchone()[0]
"""

new = """    row = cursor.fetchone()
    active_threats = row["count"] if row is not None else 0
"""

if old not in text:
    print("WARNING: active_threats fetchone()[0] line was not found.")
else:
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8", newline="\\n")
    print("SUCCESS: active_threats SQLite Row access fixed.")
    print(f"Backup: {backup.name}")
