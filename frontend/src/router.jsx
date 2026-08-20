import { Routes, Route, Navigate } from "react-router-dom";
import { lazy, Suspense } from "react";

import Login from "./Login";
import ProtectedRoute from "./ProtectedRoute";

const App = lazy(() => import("./App"));

const CustomerDashboard = lazy(
  () => import("./customer/CustomerDashboard")
);

const CustomerTimeline = lazy(
  () => import("./customer/CustomerTimeline")
);

const CustomerAnalytics = lazy(
  () => import("./customer/CustomerAnalytics")
);

const ExecutiveDashboard = lazy(
  () => import("./executive/ExecutiveDashboard")
);

export default function Router() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <Routes>

        {/* LOGIN */}
        <Route
          path="/login"
          element={<Login />}
        />

        {/* ADMIN */}
        <Route
          path="/"
          element={
            <ProtectedRoute allowedRoles={["admin"]}>
              <App />
            </ProtectedRoute>
          }
        />

        {/* CUSTOMER / ANALYST */}
        <Route
          path="/customer"
          element={
            <ProtectedRoute
              allowedRoles={["customer", "analyst"]}
            >
              <CustomerDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/timeline"
          element={
            <ProtectedRoute
              allowedRoles={["customer", "analyst"]}
            >
              <CustomerTimeline />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/analytics"
          element={
            <ProtectedRoute
              allowedRoles={["customer", "analyst"]}
            >
              <CustomerAnalytics />
            </ProtectedRoute>
          }
        />

        {/* VIEWER */}
        <Route
          path="/executive"
          element={
            <ProtectedRoute allowedRoles={["viewer"]}>
              <ExecutiveDashboard />
            </ProtectedRoute>
          }
        />

        {/* UNKNOWN ROUTES */}
        <Route
          path="*"
          element={<Navigate to="/login" replace />}
        />

      </Routes>
    </Suspense>
  );
}