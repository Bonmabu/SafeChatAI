from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

old = '''    cursor.execute("""
        SELECT category, COUNT(*) as total
        FROM incidents
        GROUP BY category
        ORDER BY total DESC
        LIMIT 3
    """)
'''

new = '''    cursor.execute("""
        SELECT
            category,
            COUNT(*) AS total,
            MAX(risk_score) AS max_risk,
            AVG(risk_score) AS avg_risk
        FROM incidents
        WHERE category IS NOT NULL
          AND LOWER(category) != 'safe'
        GROUP BY category
        ORDER BY max_risk DESC, avg_risk DESC, total DESC
        LIMIT 3
    """)
'''

if old not in text:
    raise SystemExit("ERROR: Strategy SQL block not found. NO CHANGES MADE.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: executive_strategy threat ranking repaired.")
print("Safe category is now excluded from top-threat ranking.")
print("Backup: main.py.before_strategy_fix_20260901")
