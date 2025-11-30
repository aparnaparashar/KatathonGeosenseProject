"""
Input validation utilities
"""

def validate_coordinates(lat, lon):
    """Validate latitude and longitude values"""
    try:
        lat = float(lat)
        lon = float(lon)
        
        if not (-90 <= lat <= 90):
            return False, "Latitude must be between -90 and 90"
        
        if not (-180 <= lon <= 180):
            return False, "Longitude must be between -180 and 180"
        
        return True, None
    except (TypeError, ValueError):
        return False, "Invalid coordinate format"

def validate_route_params(data):
    """Validate route calculation parameters
    Accepts location names (strings) or coordinate objects
    """
    if not isinstance(data, dict):
        return False, "Invalid request format"
    
    if 'origin' not in data or 'destination' not in data:
        return False, "Missing origin or destination"
    
    origin = data['origin']
    destination = data['destination']
    
    # Accept strings (location names) - will be geocoded
    if isinstance(origin, str) and isinstance(destination, str):
        if not origin.strip() or not destination.strip():
            return False, "Origin and destination cannot be empty"
        return True, None
    
    # Accept coordinate objects for backward compatibility
    if isinstance(origin, dict) and isinstance(destination, dict):
        if 'lat' not in origin or 'lon' not in origin:
            return False, "Origin missing lat or lon"
        
        if 'lat' not in destination or 'lon' not in destination:
            return False, "Destination missing lat or lon"
        
        # Validate coordinates
        valid, error = validate_coordinates(origin['lat'], origin['lon'])
        if not valid:
            return False, f"Invalid origin: {error}"
        
        valid, error = validate_coordinates(destination['lat'], destination['lon'])
        if not valid:
            return False, f"Invalid destination: {error}"
        
        return True, None
    
    return False, "Origin and destination must be location names (strings) or coordinate objects"

def validate_bbox(bbox_str):
    """Validate bounding box format: minLon,minLat,maxLon,maxLat"""
    try:
        parts = bbox_str.split(',')
        if len(parts) != 4:
            return False, "Bounding box must have 4 values: minLon,minLat,maxLon,maxLat"
        
        coords = [float(p) for p in parts]
        min_lon, min_lat, max_lon, max_lat = coords
        
        if not (-180 <= min_lon <= 180) or not (-180 <= max_lon <= 180):
            return False, "Longitude must be between -180 and 180"
        
        if not (-90 <= min_lat <= 90) or not (-90 <= max_lat <= 90):
            return False, "Latitude must be between -90 and 90"
        
        if min_lon >= max_lon or min_lat >= max_lat:
            return False, "Invalid bounding box: min values must be less than max values"
        
        return True, None
    except (TypeError, ValueError):
        return False, "Invalid bounding box format"
    
def validate_report_params(params):
    required = ["start_date", "end_date", "location"]
    missing = [p for p in required if p not in params]

    if missing:
        raise ValueError(f"Missing required parameters: {', '.join(missing)}")

    return True
