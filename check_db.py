import sqlite3
import glob

for f in glob.glob("*.db"):
    print("\n" + f)
    conn = sqlite3.connect(f)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    print([row[0] for row in tables])
    conn.close()
