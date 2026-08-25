from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

# ---------------------------------------------------------
# Ensure json import exists
# ---------------------------------------------------------
if "import json" not in text:
    marker = "import os"
    if marker in text:
        text = text.replace(marker, marker + "\nimport json", 1)
    else:
        text = "import json\n" + text

# ---------------------------------------------------------
# Admin authentication + control-center API
# ---------------------------------------------------------
marker = "\ndef verify_token(token: str):"

if marker not in text:
    raise SystemExit(
        "ERROR: Could not find verify_token() insertion point."
    )

if "def require_admin(" not in text:

    block = r'''
# =========================================================
# ADMIN CONTROL CENTER
# =========================================================

ADMIN_CONTROL_DEFAULTS = {
    "enforceMFA": True,
    "sessionProtection": True,
    "tenantIsolation": True,
    "threatEscalation": True,
    "realtimeAlerts": True,
    "auditLogging": True,
}


def require_admin(user=Depends(get_current_user)):
    """
    Require a valid JWT belonging to an administrator.
    Existing JWT authentication and tenant information are preserved.
    """

    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator privileges required."
        )

    return user


def ensure_admin_control_table():
    """
    Create the Admin Control Center persistence table if it does not
    already exist.

    The schema works with both SQLite and PostgreSQL.
    """

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(db_sql("""
            CREATE TABLE IF NOT EXISTS admin_control_settings (
                id INTEGER PRIMARY KEY,
                settings TEXT NOT NULL,
                updated_by TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))

        conn.commit()

    finally:
        conn.close()


def get_admin_control_settings():
    ensure_admin_control_table()

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT settings, updated_by, updated_at
                FROM admin_control_settings
                WHERE id = ?
            """),
            (1,)
        )

        row = cursor.fetchone()

        if not row:
            settings = dict(ADMIN_CONTROL_DEFAULTS)

            cursor.execute(
                db_sql("""
                    INSERT INTO admin_control_settings
                    (id, settings, updated_by)
                    VALUES (?, ?, ?)
                """),
                (
                    1,
                    json.dumps(settings),
                    "system"
                )
            )

            conn.commit()

            return {
                "settings": settings,
                "updated_by": "system",
                "updated_at": None
            }

        raw_settings = row["settings"] if hasattr(row, "keys") else row[0]
        updated_by = row["updated_by"] if hasattr(row, "keys") else row[1]
        updated_at = row["updated_at"] if hasattr(row, "keys") else row[2]

        try:
            settings = json.loads(raw_settings)
        except Exception:
            settings = dict(ADMIN_CONTROL_DEFAULTS)

        # Preserve newly introduced controls.
        for key, value in ADMIN_CONTROL_DEFAULTS.items():
            settings.setdefault(key, value)

        return {
            "settings": settings,
            "updated_by": updated_by,
            "updated_at": updated_at
        }

    finally:
        conn.close()


def save_admin_control_settings(settings, username):
    ensure_admin_control_table()

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                INSERT INTO admin_control_settings
                (id, settings, updated_by)
                VALUES (?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    settings = excluded.settings,
                    updated_by = excluded.updated_by,
                    updated_at = CURRENT_TIMESTAMP
            """),
            (
                1,
                json.dumps(settings),
                username
            )
        )

        conn.commit()

    finally:
        conn.close()


@app.get("/admin/control-center")
def admin_control_center(
    user=Depends(require_admin)
):
    """
    Return the persisted Admin Control Center configuration.
    """

    state = get_admin_control_settings()

    return {
        "success": True,
        "settings": state["settings"],
        "updated_by": state["updated_by"],
        "updated_at": state["updated_at"],
        "role": user.get("role"),
        "tenant_id": user.get("tenant_id")
    }


@app.patch("/admin/control-center")
def update_admin_control_center(
    payload: dict,
    user=Depends(require_admin)
):
    """
    Update one or more approved Admin Control Center settings.
    """

    state = get_admin_control_settings()
    settings = dict(state["settings"])

    allowed = set(ADMIN_CONTROL_DEFAULTS.keys())

    changes = {}

    for key, value in payload.items():

        if key not in allowed:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported admin control: {key}"
            )

        if not isinstance(value, bool):
            raise HTTPException(
                status_code=400,
                detail=f"Admin control '{key}' must be boolean."
            )

        if settings.get(key) != value:
            changes[key] = {
                "old": settings.get(key),
                "new": value
            }

        settings[key] = value

    save_admin_control_settings(
        settings,
        user.get("username", "admin")
    )

    if changes and settings.get("auditLogging", True):
        try:
            create_audit_log(
                action="ADMIN_CONTROL_CHANGED",
                user=user.get("username", "admin"),
                message=json.dumps(changes)
            )
        except Exception as exc:
            print(
                "ADMIN AUDIT LOG ERROR:",
                str(exc),
                flush=True
            )

    return {
        "success": True,
        "settings": settings,
        "changes": changes
    }


@app.get("/admin/permissions")
def admin_permissions(
    user=Depends(require_admin)
):
    return {
        "success": True,
        "role": user.get("role"),
        "permissions": USER_ROLES
    }


@app.get("/admin/tenants")
def admin_tenants(
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(db_sql("""
            SELECT
                tenant_id,
                company_name,
                industry
            FROM tenants
            ORDER BY tenant_id
        """))

        rows = cursor.fetchall()

        tenants = []

        for row in rows:
            tenants.append({
                "tenant_id": row["tenant_id"] if hasattr(row, "keys") else row[0],
                "company_name": row["company_name"] if hasattr(row, "keys") else row[1],
                "industry": row["industry"] if hasattr(row, "keys") else row[2],
            })

        return {
            "success": True,
            "count": len(tenants),
            "tenants": tenants
        }

    finally:
        conn.close()


@app.get("/admin/security-policies")
def admin_security_policies(
    user=Depends(require_admin)
):
    state = get_admin_control_settings()

    return {
        "success": True,
        "policies": {
            "threatEscalation": state["settings"]["threatEscalation"],
            "realtimeAlerts": state["settings"]["realtimeAlerts"],
            "enforceMFA": state["settings"]["enforceMFA"],
            "sessionProtection": state["settings"]["sessionProtection"],
            "tenantIsolation": state["settings"]["tenantIsolation"],
            "auditLogging": state["settings"]["auditLogging"],
        }
    }


@app.get("/admin/soc-configuration")
def admin_soc_configuration(
    user=Depends(require_admin)
):
    state = get_admin_control_settings()

    return {
        "success": True,
        "configuration": {
            "threatEscalation": state["settings"]["threatEscalation"],
            "realtimeAlerts": state["settings"]["realtimeAlerts"],
            "sessionProtection": state["settings"]["sessionProtection"],
            "auditLogging": state["settings"]["auditLogging"],
        }
    }


@app.get("/admin/system-settings")
def admin_system_settings(
    user=Depends(require_admin)
):
    return {
        "success": True,
        "settings": {
            "environment": os.getenv("ENVIRONMENT", "production"),
            "algorithm": ALGORITHM,
            "access_token_expire_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
            "database": os.getenv("DATABASE_URL", os.getenv("DATABASE_PATH", "configured")),
        }
    }


@app.get("/admin/audit")
def admin_audit(
    limit: int = 100,
    user=Depends(require_admin)
):
    limit = max(1, min(limit, 500))

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT
                    action,
                    "user",
                    message,
                    created_at
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
            """),
            (limit,)
        )

        rows = cursor.fetchall()

        logs = []

        for row in rows:
            logs.append({
                "action": row["action"] if hasattr(row, "keys") else row[0],
                "user": row["user"] if hasattr(row, "keys") else row[1],
                "message": row["message"] if hasattr(row, "keys") else row[2],
                "created_at": row["created_at"] if hasattr(row, "keys") else row[3],
            })

        return {
            "success": True,
            "count": len(logs),
            "logs": logs
        }

    finally:
        conn.close()

'''

    text = text.replace(marker, "\n" + block + marker, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("Admin Control Center backend API patched successfully.")

