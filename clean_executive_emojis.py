from pathlib import Path

path = Path("frontend/src/executive/ExecutiveDashboard.jsx")
text = path.read_text(encoding="utf-8")

# Repair UTF-8 mojibake such as ðŸ§ , ðŸ“‹, âš¡, etc.
for _ in range(3):
    try:
        repaired = text.encode("latin1").decode("utf-8")
        text = repaired
    except (UnicodeEncodeError, UnicodeDecodeError):
        break

# Remove emoji presentation characters while preserving normal
# technical/UI symbols such as arrows, bullets, percentages, etc.
cleaned = []

for ch in text:
    cp = ord(ch)

    is_emoji = (
        0x1F300 <= cp <= 0x1FAFF
        or 0x1F1E6 <= cp <= 0x1F1FF
        or 0x1F900 <= cp <= 0x1F9FF
        or 0x1FA70 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x26FF
        or 0x2700 <= cp <= 0x27BF
    )

    if not is_emoji:
        cleaned.append(ch)

text = "".join(cleaned)

# Remove leftover variation selectors / zero-width joiners
text = text.replace("\ufe0f", "")
text = text.replace("\u200d", "")

path.write_text(text, encoding="utf-8", newline="\n")

print("ExecutiveDashboard.jsx: mojibake repaired and emojis removed.")
