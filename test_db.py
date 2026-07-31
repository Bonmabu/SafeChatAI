from db import init_db, get_conn

print("🔄 Initializing DB...")
init_db()
print("✅ DB initialized")

print("🔄 Checking tables...")

conn = get_conn()
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cur.fetchall()

print("📦 Tables found:")
for t in tables:
    print("-", t[0])

print("\n🔄 Testing scans table...")

try:
    cur.execute("SELECT COUNT(*) FROM scans")
    count = cur.fetchone()[0]
    print("✅ scans table OK, rows =", count)

except Exception as e:
    print("❌ ERROR:", e)

conn.close()

print("\n🚀 DONE")