from pathlib import Path

path = Path("db.py")
text = path.read_text(encoding="utf-8")

marker = "def init_db():\n    conn = get_conn()\n    cursor = conn.cursor()\n"

if marker not in text:
    marker = "def init_db():\r\n    conn = get_conn()\r\n    cursor = conn.cursor()\r\n"

if marker not in text:
    raise SystemExit("ERROR: init_db marker not found. No change made.")

users_schema = r'''
    # users table and account/session-control schema
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        full_name TEXT,
        email TEXT,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'customer',
        tenant_id TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reset_token TEXT,
        reset_token_expires TIMESTAMP,
        status TEXT DEFAULT 'active',
        is_active INTEGER DEFAULT 1,
        suspended_at TIMESTAMP,
        blocked_at TIMESTAMP,
        session_version INTEGER DEFAULT 0,
        password_reset_required INTEGER DEFAULT 0,
        mfa_enabled INTEGER DEFAULT 0
    )
    """)

    for sql in [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_required INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled INTEGER DEFAULT 0"
    ]:
        try:
            cursor.execute(sql)
        except Exception:
            pass

'''

if "# users table and account/session-control schema" in text:
    print("Users schema migration already present. No change made.")
else:
    text = text.replace(marker, marker + users_schema, 1)
    path.write_text(text, encoding="utf-8", newline="\n")
    print("Users schema migration added to db.py.")
