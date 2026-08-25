from pathlib import Path

path = Path(".\db.py")
text = path.read_text(encoding="utf-8")

marker = "def get_threat_intelligence(tenant_id=\"demo\"):"

block = r'''
# ============================================================
# ADMIN USER MANAGEMENT MIGRATION
# ============================================================

def ensure_user_management_columns():
    """
    Add persistent account-management fields to users.
    Safe for existing SQLite/PostgreSQL installations.
    """
    conn = get_conn()
    cursor = conn.cursor()

    columns = [
        ("status", "TEXT DEFAULT 'active'"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("suspended_at", "TIMESTAMP"),
        ("blocked_at", "TIMESTAMP"),
        ("session_version", "INTEGER DEFAULT 0"),
        ("password_reset_required", "INTEGER DEFAULT 0"),
        ("mfa_enabled", "INTEGER DEFAULT 0"),
    ]

    try:
        for column_name, definition in columns:
            try:
                cursor.execute(
                    db_sql(
                        f"ALTER TABLE users ADD COLUMN {column_name} {definition}"
                    )
                )
            except Exception:
                # Column already exists.
                pass

        try:
            cursor.execute(db_sql("""
                UPDATE users
                SET status = 'active'
                WHERE status IS NULL OR status = ''
            """))
        except Exception:
            pass

        try:
            cursor.execute(db_sql("""
                UPDATE users
                SET is_active = 1
                WHERE is_active IS NULL
            """))
        except Exception:
            pass

        try:
            cursor.execute(db_sql("""
                UPDATE users
                SET session_version = 0
                WHERE session_version IS NULL
            """))
        except Exception:
            pass

        conn.commit()

    finally:
        conn.close()


# Run user-management migration during backend startup.
try:
    ensure_user_management_columns()
except Exception as e:
    print("USER MANAGEMENT MIGRATION WARNING:", str(e), flush=True)

'''

if "def ensure_user_management_columns():" not in text:
    if marker not in text:
        raise SystemExit("Could not find db.py insertion marker.")
    text = text.replace(marker, block + marker, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("db.py user-management migration installed.")
