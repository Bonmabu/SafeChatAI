export default function ThreatTimeline({
  timeline,
  currentPage,
  setCurrentPage,
  incidents,
  pageSize
}) {
  return (
    <div
      style={{
        marginTop: 5,
        background: "#111827",
        borderRadius: 10,
        padding: 8,
        maxHeight: "220px",
        overflow: "auto"
      }}
    >
      <h2
        style={{
          color: "#ffffff",
          fontWeight: "700"
        }}
      >
        📜 Threat Timeline
      </h2>

      {timeline.map((item, index) => (
        <div
          key={index}
          style={{
            borderBottom: "1px solid #333",
            padding: "3px 0"
          }}
        >
          <b>{item.time}</b> — {item.event}
        </div>
      ))}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginTop: 15
        }}
      >
        <button
          disabled={currentPage === 1}
          onClick={() => setCurrentPage(currentPage - 1)}
        >
          ◀ Previous
        </button>

        <span>
          Page {currentPage}
        </span>

        <button
          disabled={currentPage * pageSize >= incidents.length}
          onClick={() => setCurrentPage(currentPage + 1)}
        >
          Next ▶
        </button>
      </div>
    </div>
  );
}