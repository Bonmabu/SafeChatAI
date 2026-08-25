import React from "react";
import { Navigate, useLocation } from "react-router-dom";

export default function ProtectedRoute({
  children,
  allowedRoles = [],
}) {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");
  const location = useLocation();

  if (!token) {
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: location.pathname }}
      />
    );
  }

  if (
    allowedRoles.length > 0 &&
    !allowedRoles.includes(role)
  ) {
    return (
      <div
        style={{
          padding: 40,
          color: "white",
          background: "#0f172a",
          minHeight: "100vh",
        }}
      >
        <h2>Access Restricted</h2>
        <p>
          Your current account does not have permission to open this section.
        </p>
      </div>
    );
  }

  return children;
}
