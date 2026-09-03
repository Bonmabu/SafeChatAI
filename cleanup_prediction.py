from pathlib import Path
import shutil
from datetime import datetime

path = Path("main.py")
backup = path.with_name(
    f"main.py.before_prediction_cleanup_{datetime.now():%Y%m%d_%H%M%S}"
)

shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

old = '''        forecast = "Moderate threat activity expected."
        forecast = "Moderate threat activity expected."
'''

new = '''        forecast = "Moderate threat activity expected."
'''

if old not in text:
    print("WARNING: Duplicate forecast line not found.")
else:
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8", newline="\n")
    print("SUCCESS: Removed duplicate prediction forecast line.")
    print(f"Backup: {backup.name}")
