import sqlite3
import db

conn = sqlite3.connect(db.DATABASE_PATH)
conn.row_factory = sqlite3.Row

print("DATABASE:", db.DATABASE_PATH)
print()
print("TABLES:")

tables = conn.execute(
    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
).fetchall()

for row in tables:
    print(" -", row["name"])

print()
print("USERS:")

if any(row["name"] == "users" for row in tables):
    rows = conn.execute("""
        SELECT
            id,
            username,
            full_name,
            email,
            role,
            tenant_id,
            status,
            is_active,
            session_version
        FROM users
        ORDER BY id
    """).fetchall()

    print("Users found:", len(rows))

    for row in rows:
        print(dict(row))
else:
    print("USERS TABLE DOES NOT EXIST")

conn.close()
