from pathlib import Path

files = [
    Path("src/App.jsx"),
    Path("src/Login.jsx"),
    Path("src/executive/ExecutiveDashboard.jsx"),
]

replacements = {
    # App.jsx
    "Ã¢Å“â€¦": "✅",
    "Ã°Å¸â€Â¥": "🛡️",
    "Ã°Å¸â€˜Â¤": "👤",

    # Login.jsx
    "âš ": "⚠️",
    "â†": "←",
    "â—ˆ": "◈",
    "â€¢": "•",

    # ExecutiveDashboard.jsx
    "ðŸ“„": "📄",
    "ðŸ›¡": "🛡️",
    "ðŸŒÂ": "🌐",
    "â—Â": "●",
    "ðŸ”¥": "🔥",
    "ðŸš¨": "🚨",
    "ðŸ›¡ï¸": "🛡️",
    "ðŸ¤–": "🤖",
    "Ã°Å¸Â§Â": "🧠",
    "ðŸ§­": "🧭",
    "ðŸ”ŽÂ": "🔎",
    "ðŸ”ŽÂ®": "🔎",
    "ðŸ›¡Ã¯Â¸Â": "🛡️",
    "ðŸ“¡": "📡",
    "ðŸ“Š": "📊",
    "ðŸ–": "🖖",
    "âš¡": "⚡",
    "ðŸŽ¯": "🎯",
    "ðŸŽ¬": "🎬",
    "ðŸš¨": "🚨",
    "ðŸ”Ž": "🔎",
    "ðŸ“ˆ": "📈",
    "Ã°Å¸â€œË†": "📈",
    "ðŸŒÅ½": "🌎",
    "ðŸ“¡": "📡",
    "ðŸ¤–": "🤖",

    # Multi-pass mojibake
    "Ã°Å¸Â§Â ": "🧠",
    "Ã°Å¸Ââ€ ": "🛡️",
    "Ã¢â‚¬Â¢": "•",
    "Ã¢â€“Â¶": "▶",
    "Ã¢ÂÂ¸": "⏸",
    "Ã¢Å¸Â²": "↻",
}

for path in files:
    if not path.exists():
        print(f"SKIP: {path} not found")
        continue

    text = path.read_text(encoding="utf-8")

    original = text

    # Apply longer/more specific strings first.
    for bad, good in sorted(replacements.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(bad, good)

    path.write_text(text, encoding="utf-8", newline="\n")

    if text != original:
        print(f"FIXED: {path}")
    else:
        print(f"NO CHANGES: {path}")

print("Emoji/mojibake cleanup completed.")
