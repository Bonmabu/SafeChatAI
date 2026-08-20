import sqlite3

conn = sqlite3.connect("scams.db")

print("TOTAL USERS:", conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
print("CUSTOMER USERS:", conn.execute("SELECT COUNT(*) FROM users WHERE role = 'customer'").fetchone()[0])
print("ADMIN USERS:", conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0])
print("TOTAL TENANTS:", conn.execute("SELECT COUNT(*) FROM tenants").fetchone()[0])

print("\nREGISTERED USERS:")
for row in conn.execute("""
    SELECT id, username, full_name, email, role, tenant_id, created_at
    FROM users
    ORDER BY id
"""):
    print(row)

print("\nTENANTS:")
for row in conn.execute("""
    SELECT id, tenant_id, company_name, industry, created_at
    FROM tenants
    ORDER BY id
"""):
    print(row)

conn.close()
