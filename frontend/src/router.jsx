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

        <Route
          path="/login"
          element={<Login />}
        />

        <Route
          path="/"
          element={
            <ProtectedRoute allowedRoles={["admin"]}>
              <App />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer"
          element={
            <ProtectedRoute
              allowedRoles={["admin", "analyst", "customer"]}
            >
              <CustomerDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/timeline"
          element={
            <ProtectedRoute
              allowedRoles={["admin", "analyst", "customer"]}
            >
              <CustomerTimeline />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/analytics"
          element={
            <ProtectedRoute
              allowedRoles={["admin", "analyst", "customer"]}
            >
              <CustomerAnalytics />
            </ProtectedRoute>
          }
        />

        <Route
          path="/executive"
          element={
            <ProtectedRoute
              allowedRoles={["admin", "viewer"]}
            >
              <ExecutiveDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="*"
          element={<Navigate to="/login" replace />}
        />

      </Routes>
    </Suspense>
  );
}