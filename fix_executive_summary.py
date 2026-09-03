from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

old = '''    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE risk_score >= 90
    """)

    critical = cursor.fetchone()[0]
'''

new = '''    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM incidents
        WHERE risk_score >= 90
    """)

    row = cursor.fetchone()
    critical = row["total"] if row else 0
'''

if old not in text:
    raise SystemExit("ERROR: Target executive_summary() block was not found.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="")

print("SUCCESS: Fixed main.py executive_summary() SQLite row access.")
