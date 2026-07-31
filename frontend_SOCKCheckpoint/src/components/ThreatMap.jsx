import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import "./ThreatMap.css";

export default function ThreatMap({ incidents = [] }) {

  const points = incidents.map((incident, index) => ({
    id: incident.id ?? index,

    lat:
      incident.latitude ??
      (-1.28 + Math.random() * 30),

    lng:
      incident.longitude ??
      (36.82 + Math.random() * 40),

    category: incident.category || "Unknown",

    severity: incident.severity || "Unknown",

    score: incident.score ?? 80
  }));

  return (
    <div
      style={{
        height:"240px",
        width:"100%",
        borderRadius:"10px",
        overflow:"hidden",
        position:"relative"
      }}
    >
      <MapContainer
 center={[5,20]}
 zoom={2}
 style={{
   height:"250px",
   width:"100%"
 }}
>
        <TileLayer
          attribution="© OpenStreetMap contributors"
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {points.map((point) => (
          <CircleMarker
            key={point.id}
            center={[point.lat, point.lng]}
            radius={
              point.score >= 90
                ? 12
                : point.score >= 70
                ? 8
                : 5
            }
            pathOptions={{
              color:
                point.score >= 90
                  ? "red"
                  : point.score >= 70
                  ? "orange"
                  : "yellow",
              fillOpacity: 0.8
            }}
          >
            <Popup>
              <b>{point.category}</b>

              <br />

              Severity: {point.severity}

              <br />

              Score: {point.score}
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}