"""
External traffic API integration
Integrates with TomTom Traffic APIs - FIXED VERSION
"""

import requests
from config import Config
import logging

logger = logging.getLogger(__name__)

class TrafficAPI:
    """Interface for TomTom traffic APIs"""
    
    def __init__(self):
        self.tomtom_api_key = Config.TOMTOM_API_KEY
        self.base_url = "https://api.tomtom.com"
        
        if not self.tomtom_api_key:
            logger.warning("TomTom API key not configured")
    
    def get_traffic_flow(self, lat, lon, zoom=10):
        """
        Get traffic flow data for a location
        Returns current speed, free flow speed, and congestion level
        """
        url = f"{self.base_url}/traffic/services/4/flowSegmentData/absolute/{zoom}/json"
        
        params = {
            'key': self.tomtom_api_key,
            'point': f"{lat},{lon}",
            'unit': 'KMPH'
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if 'flowSegmentData' in data:
                segment = data['flowSegmentData']
                current_speed = segment.get('currentSpeed', 0)
                free_flow_speed = segment.get('freeFlowSpeed', 0)
                
                return {
                    'success': True,
                    'current_speed': current_speed,
                    'free_flow_speed': free_flow_speed,
                    'current_travel_time': segment.get('currentTravelTime', 0),
                    'free_flow_travel_time': segment.get('freeFlowTravelTime', 0),
                    'confidence': segment.get('confidence', 0),
                    'congestion_level': self._calculate_congestion_level(current_speed, free_flow_speed),
                    'coordinates': segment.get('coordinates', {}).get('coordinate', [])
                }
            
            return {'success': False, 'error': 'No flow data available'}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching traffic flow: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_traffic_incidents(self, bbox):
        """
        Get traffic incidents in a bounding box
        bbox format: "minLon,minLat,maxLon,maxLat"
        FIXED: Using correct API version and parameters
        """
        # Use version 5 incident details API
        url = f"{self.base_url}/traffic/services/5/incidentDetails"
        
        params = {
            'key': self.tomtom_api_key,
            'bbox': bbox,
            'fields': '{incidents{type,geometry{type,coordinates},properties{iconCategory,magnitudeOfDelay,events{description,code},startTime,endTime}}}',
            'language': 'en-GB'
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            incidents = []
            if 'incidents' in data:
                for incident in data['incidents']:
                    props = incident.get('properties', {})
                    events = props.get('events', [])
                    
                    incidents.append({
                        'type': incident.get('type'),
                        'coordinates': incident.get('geometry', {}).get('coordinates', []),
                        'category': props.get('iconCategory'),
                        'delay': props.get('magnitudeOfDelay', 0),
                        'description': events[0].get('description') if events else 'Traffic incident',
                        'start_time': props.get('startTime'),
                        'end_time': props.get('endTime')
                    })
            
            return {
                'success': True,
                'incident_count': len(incidents),
                'incidents': incidents
            }
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # No incidents found or API endpoint issue - return empty result
                logger.info(f"No incidents found in area: {bbox}")
                return {
                    'success': True,
                    'incident_count': 0,
                    'incidents': []
                }
            else:
                logger.error(f"Error fetching traffic incidents: {e}")
                return {'success': False, 'error': str(e)}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching traffic incidents: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_route_traffic(self, waypoints):
        """
        Get traffic information along a route
        waypoints: list of [lat, lon] coordinates
        """
        if len(waypoints) < 2:
            return {'success': False, 'error': 'Need at least 2 waypoints'}
        
        # Format waypoints for TomTom API
        route_points = ':'.join([f"{lat},{lon}" for lat, lon in waypoints])
        url = f"{self.base_url}/routing/1/calculateRoute/{route_points}/json"
        
        params = {
            'key': self.tomtom_api_key,
            'traffic': 'true',
            'routeType': 'fastest',
            'travelMode': 'car'
        }
        
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            if 'routes' in data and len(data['routes']) > 0:
                route = data['routes'][0]
                summary = route['summary']
                
                return {
                    'success': True,
                    'distance_meters': summary['lengthInMeters'],
                    'travel_time_seconds': summary['travelTimeInSeconds'],
                    'traffic_delay_seconds': summary.get('trafficDelayInSeconds', 0),
                    'departure_time': summary.get('departureTime'),
                    'arrival_time': summary.get('arrivalTime')
                }
            
            return {'success': False, 'error': 'No route data available'}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching route traffic: {e}")
            return {'success': False, 'error': str(e)}
    
    def search_nearby_pois(self, lat, lon, radius=5000, category=None):
        """
        Search for Points of Interest near a location
        radius: in meters (default 5km)
        category: POI category (e.g., 'restaurant', 'parking', 'gas station')
        """
        url = f"{self.base_url}/search/2/nearbySearch/.json"
        
        params = {
            'key': self.tomtom_api_key,
            'lat': lat,
            'lon': lon,
            'radius': radius,
            'limit': 100
        }
        
        if category:
            params['categorySet'] = category
        
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            pois = []
            if 'results' in data:
                for result in data['results']:
                    pos = result.get('position', {})
                    poi_data = result.get('poi', {})
                    pois.append({
                        'name': poi_data.get('name', 'Unknown'),
                        'category': poi_data.get('categories', ['Unknown'])[0] if poi_data.get('categories') else 'Unknown',
                        'latitude': pos.get('lat'),
                        'longitude': pos.get('lon'),
                        'distance': result.get('dist', 0),
                        'address': result.get('address', {}).get('freeformAddress', '')
                    })
            
            return {
                'success': True,
                'poi_count': len(pois),
                'pois': pois
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching POIs: {e}")
            return {'success': False, 'error': str(e)}
    
    def geocode_location(self, location_name):
        """
        Convert location name to coordinates using TomTom Geocoding API
        Uses /search/2/geocode/{query}.json endpoint
        
        Args:
            location_name: String name of the location (e.g., "Delhi", "Times Square")
            
        Returns:
            dict with 'success', 'lat', 'lon', and 'address' keys
        """
        url = f"{self.base_url}/search/2/geocode/{location_name}.json"
        
        params = {
            'key': self.tomtom_api_key,
            'limit': 1,
            'language': 'en-US'
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if 'results' in data and len(data['results']) > 0:
                result = data['results'][0]
                position = result.get('position', {})
                address = result.get('address', {})
                
                return {
                    'success': True,
                    'lat': position.get('lat'),
                    'lon': position.get('lon'),
                    'address': address.get('freeformAddress', location_name),
                    'full_address': address,
                    'type': result.get('type', 'unknown')
                }
            
            return {
                'success': False,
                'error': f'Location "{location_name}" not found'
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error geocoding location '{location_name}': {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _calculate_congestion_level(self, current_speed, free_flow_speed):
        """Calculate congestion level based on speed ratio"""
        if free_flow_speed == 0:
            return 'unknown'
        
        ratio = current_speed / free_flow_speed
        
        if ratio >= 0.8:
            return 'low'
        elif ratio >= 0.5:
            return 'moderate'
        elif ratio >= 0.3:
            return 'high'
        else:
            return 'severe'