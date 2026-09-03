from pathlib import Path
import re

path = Path("main.py")
text = path.read_text(encoding="utf-8")

# ---------------------------------------------------------
# FIX 1: executive_prediction probability/forecast logic
# ---------------------------------------------------------

pattern_prediction = r'''(?ms)^[ \t]*if avg >= 80:\s*
[ \t]*probability = 90\s*
[ \t]*forecast = "High probability of continued malicious activity\."\s*
[ \t]*probability = 65\s*
[ \t]*forecast = "Moderate threat activity expected\."\s*
[ \t]*else:\s*
[ \t]*probability = 30\s*
[ \t]*forecast = "Low threat activity expected\."\s*'''

replacement_prediction = '''    if avg >= 80:
        probability = 90
        forecast = "High probability of continued malicious activity."
    elif avg >= 50:
        probability = 65
        forecast = "Moderate threat activity expected."
    else:
        probability = 30
        forecast = "Low threat activity expected."'''

text, count_prediction = re.subn(
    pattern_prediction,
    replacement_prediction,
    text,
    count=1
)

print(f"Prediction logic replacements: {count_prediction}")


# ---------------------------------------------------------
# FIX 2: BLOCKED incidents SQL
# ---------------------------------------------------------

pattern_blocked = r'''(?ms)([ \t]*cursor\.execute\("""\s*
[ \t]*SELECT COUNT\(\*\) AS count\s*
[ \t]*FROM incidents\s*
[ \t]*WHERE status = 'BLOCKED')\s*
([ \t]*row = cursor\.fetchone\(\)\s*
[ \t]*blocked_attacks = row\["count"\] if row is not None else 0)'''

replacement_blocked = r'''\1
    """)
\2'''

text, count_blocked = re.subn(
    pattern_blocked,
    replacement_blocked,
    text,
    count=1
)

print(f"BLOCKED SQL replacements: {count_blocked}")


# ---------------------------------------------------------
# WRITE FILE
# ---------------------------------------------------------

path.write_text(text, encoding="utf-8", newline="\n")

print("main.py repair completed successfully.")
