import {
  MapContainer,
  TileLayer,
  CircleMarker,
  Popup,
  Polyline
} from "react-leaflet";
import "leaflet/dist/leaflet.css";

export default function AttackMap({ nodes = [] }) {
  const locations = [
    { lat: 37.7749, lng: -122.4194 },   // USA
    { lat: 51.5072, lng: -0.1276 },     // UK
    { lat: 48.8566, lng: 2.3522 },      // France
    { lat: 52.52, lng: 13.405 },        // Germany
    { lat: -1.286389, lng: 36.817223 }, // Kenya
    { lat: 35.6895, lng: 139.6917 },    // Japan
    { lat: 28.6139, lng: 77.209 },      // India
    { lat: -33.9249, lng: 18.4241 },    // South Africa
    { lat: -23.5505, lng: -46.6333 },   // Brazil
    { lat: 55.7558, lng: 37.6173 }      // Russia
  ];

  const attackLines = [];

  return (
    <MapContainer
      center={[20, 0]}
      zoom={2}
      style={{
        width: "100%",
        height: "500px",
        borderRadius: "12px"
      }}
    >
      <TileLayer
        attribution="© OpenStreetMap contributors"
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
      />

      {nodes.map((node, index) => {
        const location = locations[index % locations.length];

        if (index > 0) {
          const previous = locations[(index - 1) % locations.length];

          attackLines.push([
            [previous.lat, previous.lng],
            [location.lat, location.lng]
          ]);
        }

        return (
          <CircleMarker
            key={node.id || index}
            center={[location.lat, location.lng]}
            radius={Math.max(8, (node.score || 20) / 5)}
            pathOptions={{
              color:
                node.score >= 80
                  ? "#ff0000"
                  : node.score >= 60
                  ? "#ff9500"
                  : "#00ffc8",
              fillOpacity: 0.8
            }}
          >
            <Popup>
              <b>{node.id}</b>
              <br />
              Threat: {node.category}
              <br />
              Risk: {node.score}
              <br />
              Stage: {node.stage || "Unknown"}
              <br />
              MITRE: {node.mitre || "N/A"}
            </Popup>
          </CircleMarker>
        );
      })}

      {attackLines.map((line, i) => (
        <Polyline
          key={i}
          positions={line}
          pathOptions={{
            color: "#ff3b30",
            weight: 3,
            opacity: 0.8
          }}
        />
      ))}
    </MapContainer>
  );
}