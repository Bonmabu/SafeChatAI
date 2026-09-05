import {
  Routes,
  Route,
  Navigate,
  NavLink,
  Outlet,
} from "react-router-dom";

import { lazy, Suspense } from "react";

import Login from "./Login";
import ProtectedRoute from "./ProtectedRoute";
import OverviewDashboard from "./OverviewDashboard";
import CampaignInvestigation from "./CampaignInvestigation";
import AdminSOC from "./AdminSOC";
import ReportsIntelligence from "./ReportsIntelligence";

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

function DashboardShell() {
  const navStyle = ({ isActive }) => ({
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "10px 14px",
    borderRadius: 10,
    textDecoration: "none",
    color: isActive ? "#00ffc8" : "#cbd5e1",
    background: isActive
      ? "rgba(0,255,200,0.10)"
      : "transparent",
    border: isActive
      ? "1px solid rgba(0,255,200,0.25)"
      : "1px solid transparent",
    fontWeight: 600,
    transition: "all 0.2s ease",
  });

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#020617",
        color: "white",
      }}
    >
      <nav
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "14px 20px",
          background: "#0f172a",
          borderBottom: "1px solid #1e293b",
          flexWrap: "wrap",
        }}
      >
        <strong
          style={{
            fontSize: 20,
            marginRight: 20,
            color: "#00ffc8",
          }}
        >
          SafeChat AI
        </strong>

        <NavLink
          to="/dashboard/overview"
          style={navStyle}
        >
          Overview
        </NavLink>

        <NavLink
          to="/dashboard/customer"
          style={navStyle}
        >
          Customer SOC
        </NavLink>

        <NavLink
          to="/dashboard/campaigns"
          style={navStyle}
        >
          Campaigns
        </NavLink>

        <NavLink
          to="/dashboard/reports"
          style={navStyle}
        >
          Reports & Intelligence
        </NavLink>

        <NavLink
          to="/dashboard/executive"
          style={navStyle}
        >
          Executive / IT
        </NavLink>

        <NavLink
          to="/dashboard/admin"
          style={navStyle}
        >
          Admin SOC
        </NavLink>

        <div
          style={{
            marginLeft: "auto",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span
            style={{
              padding: "8px 12px",
              borderRadius: 8,
              background: "#111827",
              border: "1px solid #334155",
              color: "#94a3b8",
              fontSize: 12,
              fontWeight: 700,
              textTransform: "uppercase",
            }}
          >
            {localStorage.getItem("role") || "USER"}
          </span>

          <button
            type="button"
            onClick={() => {
              localStorage.removeItem("token");
              localStorage.removeItem("role");
              localStorage.removeItem("tenant_id");
              window.location.href = "/login";
            }}
            style={{
              padding: "9px 14px",
              borderRadius: 8,
              border: "1px solid #ef4444",
              background: "rgba(239,68,68,0.10)",
              color: "#fca5a5",
              cursor: "pointer",
              fontWeight: 700,
            }}
          >
            Logout
          </button>
        </div>
      </nav>

      <main style={{ padding: 10 }}>
        <Outlet />
      </main>
    </div>
  );
}

export default function Router() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <Routes>

        <Route
          path="/login"
          element={<Login />}
        />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <DashboardShell />
            </ProtectedRoute>
          }
        >
          <Route
            index
            element={
              <Navigate
                to="/dashboard/customer"
                replace
              />
            }
          />
          <Route
            path="overview"
            element={<OverviewDashboard />}
          />

          <Route
            path="campaigns"
            element={
              <ProtectedRoute>
                <CampaignInvestigation />
              </ProtectedRoute>
            }
          />


          <Route
            path="admin"
            element={
              <ProtectedRoute>
                <AdminSOC />
              </ProtectedRoute>
            }
          />

          <Route
            path="reports"
            element={
              <ProtectedRoute>
                <ReportsIntelligence />
              </ProtectedRoute>
            }
          />

          <Route
            path="customer"
            element={
              <ProtectedRoute>
                <CustomerDashboard />
              </ProtectedRoute>
            }
          />

          <Route
            path="customer/timeline"
            element={
              <ProtectedRoute>
                <CustomerTimeline />
              </ProtectedRoute>
            }
          />

          <Route
            path="customer/analytics"
            element={
              <ProtectedRoute>
                <CustomerAnalytics />
              </ProtectedRoute>
            }
          />

          <Route
            path="executive"
            element={
              <ProtectedRoute>
                <ExecutiveDashboard />
              </ProtectedRoute>
            }
          />
        </Route>

        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Navigate
                to="/dashboard/customer"
                replace
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer"
          element={
            <ProtectedRoute>
              <Navigate
                to="/dashboard/customer"
                replace
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/timeline"
          element={
            <ProtectedRoute>
              <Navigate
                to="/dashboard/customer/timeline"
                replace
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/customer/analytics"
          element={
            <ProtectedRoute>
              <Navigate
                to="/dashboard/customer/analytics"
                replace
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/executive"
          element={
            <ProtectedRoute>
              <Navigate
                to="/dashboard/executive"
                replace
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/executive-it"
          element={
            <ProtectedRoute>
              <Navigate
                to="/dashboard/executive"
                replace
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="*"
          element={
            <Navigate
              to="/dashboard/customer"
              replace
            />
          }
        />

      </Routes>
    </Suspense>
  );
}

