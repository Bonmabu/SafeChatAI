from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

start_marker = "    # Predicted threat\n"
end_marker = "    # Probability / forecast\n"

start = text.find(start_marker)
end = text.find(end_marker, start + len(start_marker))

if start == -1:
    raise SystemExit("ERROR: Predicted threat marker was not found. NO CHANGES MADE.")

if end == -1:
    raise SystemExit("ERROR: Probability forecast marker was not found. NO CHANGES MADE.")

new_block = '''    # Predicted threat
    if threat_row is not None:
        try:
            predicted = threat_row["category"]
        except (KeyError, IndexError, TypeError):
            try:
                predicted = threat_row[0]
            except (KeyError, IndexError, TypeError):
                predicted = "No active threat"
    else:
        predicted = "No active threat"

'''

new_text = text[:start] + new_block + text[end:]

path.write_text(new_text, encoding="utf-8", newline="\n")

print("SUCCESS: executive_prediction threat selection repaired.")
print("Backup: main.py.before_prediction_fix_20260901")
