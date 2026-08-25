from pathlib import Path

path = Path(r".\src\AdminSOC.jsx")
text = path.read_text(encoding="utf-8")

# 1. Add useEffect
text = text.replace(
    'import { useState } from "react";',
    'import { useEffect, useState } from "react";',
    1
)

# 2. Replace the existing toggleControl function
old = '''  const toggleControl = (key) => {
    setControls((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };'''

new = '''  const API_BASE =
    import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

  const getAuthHeaders = () => {
    const token =
      localStorage.getItem("token") ||
      localStorage.getItem("access_token") ||
      localStorage.getItem("jwt");

    return {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  };

  useEffect(() => {
    let cancelled = false;

    const loadAdminControls = async () => {
      try {
        const response = await fetch(
          `${API_BASE}/admin/control-center`,
          {
            method: "GET",
            headers: getAuthHeaders(),
          }
        );

        if (!response.ok) {
          throw new Error(`Admin control load failed: ${response.status}`);
        }

        const data = await response.json();

        if (!cancelled && data?.settings) {
          setControls((current) => ({
            ...current,
            ...data.settings,
          }));
        }
      } catch (error) {
        console.error("ADMIN CONTROL CENTER LOAD ERROR:", error);
      }
    };

    loadAdminControls();

    return () => {
      cancelled = true;
    };
  }, []);

  const toggleControl = async (key) => {
    const nextValue = !controls[key];

    setControls((current) => ({
      ...current,
      [key]: nextValue,
    }));

    try {
      const response = await fetch(
        `${API_BASE}/admin/control-center`,
        {
          method: "PATCH",
          headers: getAuthHeaders(),
          body: JSON.stringify({
            [key]: nextValue,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`Admin control update failed: ${response.status}`);
      }

      const data = await response.json();

      if (data?.settings) {
        setControls((current) => ({
          ...current,
          ...data.settings,
        }));
      }

      setLastAction(
        `${key} ${nextValue ? "enabled" : "disabled"}`
      );
    } catch (error) {
      console.error("ADMIN CONTROL CENTER UPDATE ERROR:", error);

      // Roll back optimistic UI change
      setControls((current) => ({
        ...current,
        [key]: !nextValue,
      }));

      setLastAction(`Failed to update ${key}`);
    }
  };'''

if old not in text:
    raise SystemExit("ERROR: Existing toggleControl block was not found.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("AdminSOC Admin Control Center API wiring installed successfully.")
