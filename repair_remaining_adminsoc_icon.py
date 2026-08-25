from pathlib import Path
import re

path = Path(r".\frontend\src\AdminSOC.jsx")
text = path.read_text(encoding="utf-8-sig")

pattern = r'(<div className="admin-control-icon">)[^<]*(</div>\s*<div[^>]*>\s*<h3>Tenant Governance</h3>)'

text, count = re.subn(
    pattern,
    r'\1🏢\2',
    text,
    flags=re.MULTILINE
)

path.write_text(text, encoding="utf-8", newline="\n")

print(f"Tenant Governance icon repairs: {count}")
