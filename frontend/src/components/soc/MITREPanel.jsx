export default function MITREPanel({ mitreInfo }) {

  if (!mitreInfo) {
    return null;
  }

  return (
    <div
      style={{
        marginTop: 10,
        background: "#111827",
        borderRadius: 10,
        padding: 10
      }}
    >
      <h2
        style={{
          color: "#ffffff",
          fontWeight: "700"
        }}
      >
        🛡 MITRE ATT&CK Mapping
      </h2>

      <table style={{ width: "100%" }}>
        <tbody>
          <tr>
            <td><b>Tactic</b></td>
            <td>{mitreInfo.tactic}</td>
          </tr>

          <tr>
            <td><b>Technique</b></td>
            <td>{mitreInfo.technique}</td>
          </tr>

          <tr>
            <td><b>Name</b></td>
            <td>{mitreInfo.name}</td>
          </tr>
        </tbody>
      </table>

    </div>
  );
}