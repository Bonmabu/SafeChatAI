import React from "react";
import { Navigate } from "react-router-dom";

export default function ProtectedRoute({
  children,
  allowedRoles = [],
}) {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (
    allowedRoles.length > 0 &&
    !allowedRoles.includes(role)
  ) {
    if (role === "customer") {
      return <Navigate to="/customer" replace />;
    }

    if (role === "admin") {
      return <Navigate to="/" replace />;
    }

    if (role === "viewer") {
      return <Navigate to="/executive" replace />;
    }

    if (role === "analyst") {
      return <Navigate to="/customer" replace />;
    }

    return <Navigate to="/login" replace />;
  }

  return children;
}