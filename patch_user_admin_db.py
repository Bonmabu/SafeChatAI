from pathlib import Path

path = Path(".\db.py")
text = path.read_text(encoding="utf-8")

marker = "        cursor.execute(\"\"\"\n        CREATE TABLE IF NOT EXISTS threat_iocs"

migration = r'''
        # ---------------------------------------------------------
        # USER ADMINISTRATION MIGRATION
        # ---------------------------------------------------------
        # These fields support enterprise account lifecycle control:
        # ACTIVE / SUSPENDED / BLOCKED / DEACTIVATED,
        # MFA state, forced password reset and session invalidation.
        # ---------------------------------------------------------

        user_admin_columns = [
            ("status", "TEXT DEFAULT 'ACTIVE'"),
            ("mfa_enabled", "INTEGER DEFAULT 0"),
            ("force_password_change", "INTEGER DEFAULT 0"),
            ("session_version", "INTEGER DEFAULT 1"),
            ("last_login", "TIMESTAMP"),
            ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ("blocked_reason", "TEXT"),
            ("suspended_reason", "TEXT"),
        ]

        if DATABASE_URL:
            for column_name, column_definition in user_admin_columns:
                try:
                    cursor.execute(
                        f"""
                        ALTER TABLE users
                        ADD COLUMN IF NOT EXISTS {column_name}
                        {column_definition}
                        """
                    )
                except Exception as e:
                    print(
                        f"users migration ({column_name}): {e}",
                        flush=True
                    )
        else:
            try:
                cursor.execute("PRAGMA table_info(users)")
                existing_user_columns = {
                    row["name"] for row in cursor.fetchall()
                }

                for column_name, column_definition in user_admin_columns:
                    if column_name not in existing_user_columns:
                        try:
                            cursor.execute(
                                f"""
                                ALTER TABLE users
                                ADD COLUMN {column_name}
                                {column_definition}
                                """
                            )
                            print(
                                f"Added users.{column_name}",
                                flush=True
                            )
                        except Exception as e:
                            print(
                                f"users migration ({column_name}): {e}",
                                flush=True
                            )
            except Exception as e:
                print(
                    f"users schema inspection failed: {e}",
                    flush=True
                )

        # Normalize existing users to an active state where status
        # was newly introduced.
        try:
            cursor.execute("""
                UPDATE users
                SET status = 'ACTIVE'
                WHERE status IS NULL OR TRIM(status) = ''
            """)
        except Exception as e:
            print(
                f"users status normalization: {e}",
                flush=True
            )

        conn.commit()

'''

if migration.strip() in text:
    print("User administration migration already exists.")
else:
    if marker not in text:
        raise SystemExit(
            "ERROR: Could not find the threat_iocs table marker in db.py."
        )

    text = text.replace(marker, migration + marker, 1)
    path.write_text(text, encoding="utf-8", newline="\n")

    print("SUCCESS: User administration database migration added.")
