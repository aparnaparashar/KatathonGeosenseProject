import React, { useEffect, useRef } from "react";
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  Polyline,
  useMap,
} from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "./MapComponent.css";

// Fix marker issue for Leaflet
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
});

// Load key from .env
const API_KEY =
  import.meta.env.VITE_TOMTOM_API_KEY || "P9qBEYuHG256dbid1aYvjznVuZNXnc5h";

// Component to handle map bounds updates
function MapBounds({ routes, origin, destination }) {
  const map = useMap();

  useEffect(() => {
    if (routes && routes.length > 0) {
      // Collect all points from all routes
      const allPoints = [];

      routes.forEach((route) => {
        if (route.geometry && route.geometry.length > 0) {
          allPoints.push(...route.geometry);
        }
      });

      if (origin && origin.lat && origin.lon) {
        allPoints.push([origin.lat, origin.lon]);
      }
      if (destination && destination.lat && destination.lon) {
        allPoints.push([destination.lat, destination.lon]);
      }

      if (allPoints.length > 0) {
        const bounds = L.latLngBounds(allPoints);
        map.fitBounds(bounds, { padding: [50, 50] });
      }
    }
  }, [routes, origin, destination, map]);

  return null;
}

const MapComponent = ({
  center = [28.6139, 77.209], // Default: Delhi, India
  zoom = 12,
  markers = [],
  routes = [], // Array of route objects with { geometry, color, id }
  selectedRouteId = null,
  origin = null,
  destination = null,
  className = "",
}) => {
  // Validate API key
  if (!API_KEY) {
    return (
      <div className="map-container error">
        <div className="error-message">
          <h3>Map Unavailable</h3>
          <p>TomTom API key is not configured.</p>
          <p>Please check your environment variables.</p>
        </div>
      </div>
    );
  }

  // Convert geometry format: [lat, lon] arrays to [lat, lng] for Leaflet
  const formatCoordinates = (geometry) => {
    if (!geometry || geometry.length === 0) return [];
    return geometry
      .map((point) => {
        if (Array.isArray(point)) {
          return [point[0], point[1]]; // [lat, lon]
        }
        if (point.lat && point.lon) {
          return [point.lat, point.lon];
        }
        return null;
      })
      .filter(Boolean);
  };

  return (
    <div className={`map-container ${className}`}>
      <MapContainer
        center={center}
        zoom={zoom}
        style={{ height: "100%", width: "100%" }}
        scrollWheelZoom={true}
      >
        {/* TomTom Tile Layer with recommended parameters */}
        <TileLayer
          url={`https://api.tomtom.com/map/1/tile/basic/main/{z}/{x}/{y}.png?key=${API_KEY}&tileSize=256&view=Unified`}
          attribution='&copy; <a href="https://www.tomtom.com/copyright/" target="_blank">TomTom</a>'
          minZoom={0}
          maxZoom={22}
        />

        {/* Auto-fit bounds when routes change */}
        <MapBounds routes={routes} origin={origin} destination={destination} />

        {/* Draw routes as polylines */}
        {routes.map((route) => {
          if (!route.geometry || route.geometry.length === 0) return null;

          const coordinates = formatCoordinates(route.geometry);
          const isSelected = selectedRouteId === route.id;

          return (
            <Polyline
              key={route.id || route.type}
              positions={coordinates}
              color={route.color || "#1E90FF"}
              weight={isSelected ? 8 : 6}
              opacity={0.8}
            />
          );
        })}

        {/* Origin marker */}
        {origin && origin.lat && origin.lon && (
          <Marker position={[origin.lat, origin.lon]}>
            <Popup>
              <div className="custom-popup">
                <strong>Origin</strong>
                <br />
                {typeof origin === "string"
                  ? origin
                  : `${origin.lat.toFixed(4)}, ${origin.lon.toFixed(4)}`}
              </div>
            </Popup>
          </Marker>
        )}

        {/* Destination marker */}
        {destination && destination.lat && destination.lon && (
          <Marker position={[destination.lat, destination.lon]}>
            <Popup>
              <div className="custom-popup">
                <strong>Destination</strong>
                <br />
                {typeof destination === "string"
                  ? destination
                  : `${destination.lat.toFixed(4)}, ${destination.lon.toFixed(
                      4
                    )}`}
              </div>
            </Popup>
          </Marker>
        )}

        {/* Additional markers */}
        {markers.map((marker, index) => (
          <Marker key={index} position={marker.position}>
            {marker.popup && (
              <Popup>
                <div className="custom-popup">{marker.popup}</div>
              </Popup>
            )}
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
};

export default MapComponent;
