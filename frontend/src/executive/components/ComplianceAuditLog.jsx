import React from "react";

export default function ComplianceAuditLog({ logs = [] }) {
  return (
    <div
      style={{
        marginTop: 30,
        background: "#111827",
        borderRadius: 12,
        padding: 20,
        color: "white"
      }}
    >
      <h3>📋 Compliance Audit Log</h3>

      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          marginTop: 15
        }}
      >
        <thead>
          <tr>
            <th align="left">Time</th>
            <th align="left">Framework</th>
            <th align="left">Action</th>
            <th align="left">User</th>
            <th align="left">Status</th>
          </tr>
        </thead>

        <tbody>
          {logs.length === 0 ? (
            <tr>
              <td colSpan="5" style={{ padding: 15 }}>
                No audit records available.
              </td>
            </tr>
          ) : (
            logs.map((log, index) => (
              <tr key={index}>
                <td>{log.time}</td>
                <td>{log.framework ?? "Enterprise"}</td>
                <td>{log.action}</td>
                <td>{log.user}</td>
                <td>{log.status}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}