from pathlib import Path
import re

path = Path("frontend/src/executive/ExecutiveDashboard.jsx")
text = path.read_text(encoding="utf-8")

# Remove the remaining literal mojibake emoji sequences.
patterns = [
    r"ðŸ§.",
    r"ðŸ†.",
    r"ðŸ“.",
    r"ðŸ”..",
    r"ðŸŽ.",
    r"âš.",
    r"â–.",
    r"â¸.",
    r"âŸ.",
]

for pattern in patterns:
    text = re.sub(pattern + r"[ \t]*", "", text)

path.write_text(text, encoding="utf-8", newline="\n")

print("Remaining ExecutiveDashboard mojibake removed.")
