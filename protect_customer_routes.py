from pathlib import Path
import re

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

pattern = re.compile(
    r'(?m)^(@app\.(?:get|post|put|delete|patch)\("/customer/[^"]+"\))$'
)

matches = list(pattern.finditer(text))
changed = 0

for m in reversed(matches):
    original = m.group(1)

    if "dependencies=" in original:
        continue

    replacement = original[:-1] + ', dependencies=[Depends(require_customer_access)])'
    text = text[:m.start(1)] + replacement + text[m.end(1):]
    changed += 1

path.write_text(text, encoding="utf-8", newline="\n")

print(f"Protected {changed} customer API routes.")
