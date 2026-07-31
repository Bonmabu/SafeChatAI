import { useEffect, useState } from "react";

export default function CustomerIncidents() {
  const [incidents, setIncidents] = useState([]);

  useEffect(() => {
    const API =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

fetch(`${API}/customer/incidents?tenant_id=demo`)
      .then(res => res.json())
      .then(setIncidents);
  }, []);

  return (
    <div style={{ padding: 20 }}>
      <h2>Customer Incidents</h2>

      <table border="1" cellPadding="8">
        <thead>
          <tr>
            <th>ID</th>
            <th>Category</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Created</th>
          </tr>
        </thead>

        <tbody>
          {incidents.map(i => (
            <tr key={i.id}>
              <td>{i.id}</td>
              <td>{i.category}</td>
              <td>{i.severity}</td>
              <td>{i.status}</td>
              <td>{i.created_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}