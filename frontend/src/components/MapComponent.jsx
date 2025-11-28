import React from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
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
const API_KEY = import.meta.env.VITE_TOMTOM_API_KEY;

const MapComponent = ({
  center = [28.6139, 77.2090], // Default: Delhi, India
  zoom = 12,
  markers = [],
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

        {/* Add markers */}
        {markers.map((marker, index) => (
          <Marker key={index} position={marker.position}>
            {marker.popup && (
              <Popup>
                <div className="custom-popup">
                  {marker.popup}
                </div>
              </Popup>
            )}
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
};

export default MapComponent;