from pathlib import Path

path = Path(r"frontend/src/customer/CustomerDashboard.jsx")

replacements = {
    "ðŸ›¡": "🛡️",
    "ðŸš¨": "🚨",
    "ðŸ“ˆ": "📈",
    "ðŸ§ ": "🧠",
    "âœ…": "✅",
    "ðŸ”¥": "🔥",
    "â–¶": "▶️",
    "ðŸ¤–": "🤖",
    "ðŸŒ": "🌐",
    "ðŸ§¬": "🧬",
    "ðŸ”": "🔍",
    "ðŸŽ¯": "🎯",
    "ðŸ“–": "📖",
    "ðŸŒ±": "🌱",
    "â¸": "⏸️",
    "â¹": "⏹️",
    "â†’": "→",
}

text = path.read_text(encoding="utf-8")

original = text

for bad, good in replacements.items():
    text = text.replace(bad, good)

path.write_text(text, encoding="utf-8", newline="\n")

print("CustomerDashboard.jsx emoji repair complete.")
print("Changed:", text != original)
