import { Routes, Route, Navigate } from "react-router-dom";
import Login from "./Login";
import { lazy, Suspense } from "react";

const App = lazy(() => import("./App"));
const CustomerDashboard = lazy(() => import("./customer/CustomerDashboard"));
const CustomerTimeline = lazy(() => import("./customer/CustomerTimeline"));
const CustomerAnalytics = lazy(() => import("./customer/CustomerAnalytics"));
const ExecutiveDashboard = lazy(() => import("./executive/ExecutiveDashboard"));
function ProtectedRoute({ children }) {
  const token = localStorage.getItem("token");

  return token ? children : <Navigate to="/login" replace />;
}

export default function Router() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <Routes>

        <Route path="/login" element={<Login />} />

        <Route
          path="/"
          element={
            <ProtectedRoute>
              <App />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer"
          element={
            <ProtectedRoute>
              <CustomerDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/timeline"
          element={
            <ProtectedRoute>
              <CustomerTimeline />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/analytics"
          element={
            <ProtectedRoute>
              <CustomerAnalytics />
            </ProtectedRoute>
          }
        />

        <Route
          path="/executive"
          element={
            <ProtectedRoute>
              <ExecutiveDashboard />
            </ProtectedRoute>
          }
        />

      </Routes>
    </Suspense>
  );
}