from pathlib import Path

path = Path(r".\frontend\src\AdminSOC.jsx")

text = path.read_text(encoding="utf-8-sig")

replacements = {
    "ðŸ›¡ï¸": "🛡️",
    "âœ“": "✓",
    "ðŸ‘‘": "👑",
    "ðŸš¨": "🚨",
    "ðŸ¤–": "🤖",
    "ðŸ”§": "🔧",
    "â†»": "↻",
    "ðŸ”": "🔐",
    "ðŸ¢": "🏢",
    "âš™ï¸": "⚙️",
    "ðŸ“‹": "📋",
    "ðŸ“¡": "📡",
    "ðŸ“œ": "📜",
    "ðŸš€": "🚀",
}

total = 0

for bad, good in replacements.items():
    count = text.count(bad)
    if count:
        text = text.replace(bad, good)
        total += count
        print(f"Repaired {count} occurrence(s): {bad} -> {good}")

path.write_text(text, encoding="utf-8", newline="\n")

print(f"\nTotal emoji repairs: {total}")
