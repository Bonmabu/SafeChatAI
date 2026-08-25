from pathlib import Path
import re

path = Path(r"frontend/src/executive/ExecutiveDashboard.jsx")

text = path.read_text(encoding="utf-8-sig")

# Repair the mojibake that can be safely decoded through Windows-1252.
# Do this one pass at a time and only keep a conversion when it reduces
# the known mojibake markers.
def score(s):
    markers = [
        "Ã", "Â", "â", "ð", "Å", "Ÿ",
        "š", "ž", "œ", "™"
    ]
    return sum(s.count(x) for x in markers)

for _ in range(4):
    old_score = score(text)

    try:
        candidate = text.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        break

    if score(candidate) < old_score:
        text = candidate
    else:
        break

# Exact repairs for truncated mojibake sequences visible in this file.
replacements = {
    "ðŸ“„": "\U0001F4C4",
    "ðŸ›¡": "\U0001F6E1",
    "ðŸ›¡ï¸": "\U0001F6E1\uFE0F",
    "ðŸŒ": "\U0001F310",
    "ðŸ§ ": "\U0001F9E0",
    "ðŸ§­": "\U0001F9ED",
    "ðŸ†": "\U0001F195",
    "ðŸ”": "\U0001F50E",
    "ðŸ”¥": "\U0001F525",
    "ðŸš¨": "\U0001F6A8",
    "ðŸ¤–": "\U0001F916",
    "ðŸ“¡": "\U0001F4E1",
    "ðŸ“Š": "\U0001F4CA",
    "ðŸŽ–": "\U0001F3D6",
    "ðŸŽ¯": "\U0001F3AF",
    "ðŸŽ¬": "\U0001F3AC",
    "ðŸŒŽ": "\U0001F30E",
    "ðŸ¤": "\U0001F9E0",
    "ðŸŸ¢": "\U0001F7E2",
    "âš¡": "\u26A1",
    "âšª": "\u26AA",
    "â—": "\u25CF",
    "â€”": "\u2014",
    "Ã¢â‚¬â€": "\u2014",
    "Ã¢â‚¬â€ž": "\u2014",
}

for old, new in replacements.items():
    text = text.replace(old, new)

# Remove the remaining Executive User Directory block.
# This starts at KPICards and ends immediately before ExecutiveWarRoom.
pattern = r'(?s)<KPICards\s+kpis=\{kpis\}\s*/>\s*.*?(?=<ExecutiveWarRoom\b)'

text, removed = re.subn(pattern, "", text, count=1)

if removed:
    print("Removed remaining Executive User Directory / KPICards section.")
else:
    print("WARNING: User Directory/KPICards block was not found.")

path.write_text(text, encoding="utf-8", newline="\n")

print("Executive Dashboard cleanup completed.")
