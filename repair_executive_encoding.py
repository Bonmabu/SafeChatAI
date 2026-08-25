from pathlib import Path

path = Path(r"frontend/src/executive/ExecutiveDashboard.jsx")

text = path.read_text(encoding="utf-8-sig")

def mojibake_score(s):
    markers = [
        "Ã", "Â", "â", "ð", "Å", "¤", "™", "œ", "š", "ž"
    ]
    return sum(s.count(x) for x in markers)

fixed_rounds = 0

for _ in range(5):
    before_score = mojibake_score(text)

    try:
        candidate = text.encode("latin1").decode("utf-8")
    except UnicodeError:
        break

    after_score = mojibake_score(candidate)

    if after_score < before_score:
        text = candidate
        fixed_rounds += 1
    else:
        break

path.write_text(text, encoding="utf-8", newline="\n")

print(f"Emoji/text encoding repair completed. Rounds: {fixed_rounds}")
