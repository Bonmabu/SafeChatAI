import { useEffect, useState } from "react";
import axios from "axios";
import CustomerNav from "./CustomerNav";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend
} from "recharts";

const API =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

const COLORS = [
  "#2563eb",
  "#dc2626",
  "#16a34a",
  "#ea580c",
  "#9333ea",
  "#0891b2"
];

export default function CustomerAnalytics() {

  const tenantId = "demo";

  const [trends, setTrends] = useState([]);
  const [categories, setCategories] = useState([]);
  const [status, setStatus] = useState([]);
  const [dashboard, setDashboard] = useState({});

  useEffect(() => {
    loadAnalytics();

    const interval = setInterval(loadAnalytics, 5000);

    return () => clearInterval(interval);
  }, []);

  async function loadAnalytics() {

    try {

      const [
  dashboardRes,
  trendRes,
  categoryRes,
  statusRes
] = await Promise.all([
axios.get(`${API}/customer/dashboard`, {
  params: { tenant_id: tenantId }
}),

        axios.get(`${API}/customer/trends`, {
          params: { tenant_id: tenantId }
        }),

        axios.get(`${API}/customer/categories`, {
          params: { tenant_id: tenantId }
        }),

        axios.get(`${API}/customer/status`, {
          params: { tenant_id: tenantId }
        })

      ]);
setDashboard(dashboardRes.data);

      setTrends(trendRes.data);
      setCategories(categoryRes.data);
      setStatus(statusRes.data);

    } catch (err) {
      console.error(err);
    }
  }

  return (
    <div style={{ padding:30 }}>

      <h1>📊 Customer Threat Analytics</h1>
<CustomerNav />
<div
  style={{
    display: "grid",
    gridTemplateColumns: "repeat(4,1fr)",
    gap: 20,
    margin: "25px 0"
  }}
>
  <MetricCard
    title="Security Score"
    value={`${dashboard.security_score ?? 100}%`}
  />

  <MetricCard
    title="Open Incidents"
    value={dashboard.open_incidents ?? 0}
  />

  <MetricCard
    title="Alerts"
    value={dashboard.total_alerts ?? 0}
  />

  <MetricCard
    title="Scans"
    value={dashboard.total_scans ?? 0}
  />
</div>

      <div
        style={{
          display:"grid",
          gridTemplateColumns:"1fr 1fr",
          gap:25
        }}
      >

        <div
          style={{
            background:"#111827",
            padding:20,
            borderRadius:10
          }}
        >
          <h2 style={{color:"white"}}>Daily Threat Trend</h2>

          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trends}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="day" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#2563eb"
              />
            </LineChart>
          </ResponsiveContainer>

        </div>

        <div
          style={{
            background:"#111827",
            padding:20,
            borderRadius:10
          }}
        >

          <h2 style={{color:"white"}}>Threat Categories</h2>

          <ResponsiveContainer width="100%" height={300}>
            <PieChart>

              <Pie
                data={categories}
                dataKey="count"
                nameKey="category"
                outerRadius={110}
                label
              >
                {categories.map((entry,index)=>(
                  <Cell
                    key={index}
                    fill={COLORS[index % COLORS.length]}
                  />
                ))}
              </Pie>

              <Tooltip/>

            </PieChart>
          </ResponsiveContainer>

        </div>

        <div
          style={{
            background:"#111827",
            padding:20,
            borderRadius:10,
            gridColumn:"span 2"
          }}
        >

          <h2 style={{color:"white"}}>Incident Status</h2>

          <ResponsiveContainer width="100%" height={320}>

            <BarChart data={status}>

              <CartesianGrid strokeDasharray="3 3"/>

              <XAxis dataKey="status"/>

              <YAxis/>

              <Tooltip/>

              <Legend/>

              <Bar
                dataKey="count"
                fill="#16a34a"
              />

            </BarChart>

          </ResponsiveContainer>

        </div>

      </div>

    </div>
  );

}
function MetricCard({ title, value }) {
  return (
    <div
      style={{
        background: "#1e293b",
        borderRadius: 10,
        padding: 20,
        textAlign: "center",
        color: "white"
      }}
    >
      <h3>{title}</h3>

      <h1 style={{ color: "#22d3ee" }}>
        {value}
      </h1>
    </div>
  );
}