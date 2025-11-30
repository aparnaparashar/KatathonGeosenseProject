"""
Routing engine service
Calculates fastest, cheapest, and eco-friendly routes using TomTom API
"""

import requests
from config import Config
from services.traffic_api import TrafficAPI
import logging

logger = logging.getLogger(__name__)

class RoutingEngine:
    """Calculate and compare different route options"""
    
    def __init__(self):
        self.api_key = Config.TOMTOM_API_KEY
        self.base_url = "https://api.tomtom.com"
        self.cost_per_km = Config.COST_PER_KM
        self.co2_per_km = Config.CO2_PER_KM_CAR
        self.traffic_api = TrafficAPI()  # For geocoding
    
    def _normalize_coordinates(self, point):
        """
        Normalize coordinate input to [lat, lon] format
        Accepts: 
        - Location name (string): "Delhi", "Times Square" -> geocodes it
        - [lat, lon] list
        - {"lat": x, "lon": y} dict
        - {"lat": x, "lng": y} dict
        - {"latitude": x, "longitude": y} dict
        """
        # If it's a string, treat it as a location name and geocode it
        if isinstance(point, str):
            logger.info(f"Geocoding location name: {point}")
            geocode_result = self.traffic_api.geocode_location(point)
            if not geocode_result.get('success'):
                raise ValueError(f"Geocoding failed for '{point}': {geocode_result.get('error', 'Unknown error')}")
            return [geocode_result['lat'], geocode_result['lon']]
        
        if isinstance(point, (list, tuple)) and len(point) == 2:
            return [float(point[0]), float(point[1])]
        
        if isinstance(point, dict):
            # Try different key combinations
            lat = point.get('lat') or point.get('latitude')
            lon = point.get('lon') or point.get('lng') or point.get('longitude')
            
            if lat is not None and lon is not None:
                return [float(lat), float(lon)]
            
            raise ValueError(f"Cannot extract coordinates from dict: {point}")
        
        raise ValueError(f"Invalid coordinate format: {type(point)} - {point}")
    
    def calculate_fastest_route(self, origin, destination):
        """
        Calculate the fastest route using real-time traffic
        Accepts various coordinate formats
        """
        # Normalize coordinates first
        origin_norm = self._normalize_coordinates(origin)
        destination_norm = self._normalize_coordinates(destination)
        
        url = f"{self.base_url}/routing/1/calculateRoute/{origin_norm[0]},{origin_norm[1]}:{destination_norm[0]},{destination_norm[1]}/json"
        
        params = {
            'key': self.api_key,
            'traffic': 'true',
            'routeType': 'fastest',
            'travelMode': 'car',
            'departAt': 'now',
            'computeTravelTimeFor': 'all'
        }
        
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            if 'routes' in data and len(data['routes']) > 0:
                route = data['routes'][0]
                return self._format_route_response(route, 'fastest')
            
            return {'success': False, 'error': 'No route found'}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calculating fastest route: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in fastest route: {e}")
            return {'success': False, 'error': str(e)}
    
    def calculate_cheapest_route(self, origin, destination):
        """
        Calculate the cheapest route (shortest distance + avoid tolls)
        Minimizes fuel cost
        """
        # Normalize coordinates first
        origin_norm = self._normalize_coordinates(origin)
        destination_norm = self._normalize_coordinates(destination)
        
        url = f"{self.base_url}/routing/1/calculateRoute/{origin_norm[0]},{origin_norm[1]}:{destination_norm[0]},{destination_norm[1]}/json"
        
        params = {
            'key': self.api_key,
            'traffic': 'false',
            'routeType': 'shortest',
            'travelMode': 'car',
            'avoid': 'tollRoads'
        }
        
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            if 'routes' in data and len(data['routes']) > 0:
                route = data['routes'][0]
                result = self._format_route_response(route, 'cheapest')
                result['savings_note'] = 'Avoids toll roads and uses shortest distance'
                return result
            
            return {'success': False, 'error': 'No route found'}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calculating cheapest route: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in cheapest route: {e}")
            return {'success': False, 'error': str(e)}
    
    def calculate_eco_route(self, origin, destination):
        """
        Calculate the most eco-friendly route
        Optimizes for fuel efficiency and lower emissions
        """
        # Normalize coordinates first
        origin_norm = self._normalize_coordinates(origin)
        destination_norm = self._normalize_coordinates(destination)
        
        url = f"{self.base_url}/routing/1/calculateRoute/{origin_norm[0]},{origin_norm[1]}:{destination_norm[0]},{destination_norm[1]}/json"
        
        params = {
            'key': self.api_key,
            'traffic': 'true',
            'routeType': 'eco',
            'travelMode': 'car',
            'vehicleEngineType': 'combustion',
            'constantSpeedConsumptionInLitersPerHundredkm': '6.5,80'
        }
        
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            if 'routes' in data and len(data['routes']) > 0:
                route = data['routes'][0]
                result = self._format_route_response(route, 'eco')
                result['eco_note'] = 'Optimized for fuel efficiency and lower emissions'
                return result
            
            return {'success': False, 'error': 'No route found'}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calculating eco route: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in eco route: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_all_routes(self, origin, destination):
        """
        Get all three route types for pooling page
        Returns fastest, cheapest, and eco-friendly routes
        """
        try:
            # Normalize coordinates once
            origin_norm = self._normalize_coordinates(origin)
            destination_norm = self._normalize_coordinates(destination)
            
            fastest = self.calculate_fastest_route(origin_norm, destination_norm)
            cheapest = self.calculate_cheapest_route(origin_norm, destination_norm)
            eco = self.calculate_eco_route(origin_norm, destination_norm)
            
            return {
                'success': True,
                'routes': {
                    'fastest': fastest,
                    'cheapest': cheapest,
                    'eco_friendly': eco
                },
                'origin': {'lat': origin_norm[0], 'lon': origin_norm[1]},
                'destination': {'lat': destination_norm[0], 'lon': destination_norm[1]}
            }
            
        except Exception as e:
            logger.error(f"Error in get_all_routes: {e}")
            return {'success': False, 'error': str(e)}
    
    def compare_routes(self, origin, destination):
        """
        Compare all three route types
        Returns fastest, cheapest, and eco-friendly routes with comparison
        Accepts location names (strings) or coordinates
        """
        try:
            # Normalize coordinates once (geocodes if strings are provided)
            origin_norm = self._normalize_coordinates(origin)
            destination_norm = self._normalize_coordinates(destination)
            
            fastest = self.calculate_fastest_route(origin_norm, destination_norm)
            cheapest = self.calculate_cheapest_route(origin_norm, destination_norm)
            eco = self.calculate_eco_route(origin_norm, destination_norm)
            
            # Generate comparison metrics
            comparison = self._generate_comparison(fastest, cheapest, eco)
            
            return {
                'success': True,
                'fastest': fastest,
                'cheapest': cheapest,
                'eco': eco,  # Frontend expects 'eco' not 'eco_friendly'
                'comparison': comparison,
                'origin': {'lat': origin_norm[0], 'lon': origin_norm[1]},
                'destination': {'lat': destination_norm[0], 'lon': destination_norm[1]}
            }
            
        except Exception as e:
            logger.error(f"Error in compare_routes: {e}")
            return {'success': False, 'error': str(e)}
    
    def _format_route_response(self, route, route_type):
        """Format TomTom route response into standardized format"""
        # Check if route is an error response
        if not route.get('success', True):
            return route
            
        summary = route.get('summary', {})
        legs = route.get('legs', [])
        
        distance_km = summary.get('lengthInMeters', 0) / 1000
        duration_minutes = summary.get('travelTimeInSeconds', 0) / 60
        traffic_delay = summary.get('trafficDelayInSeconds', 0) / 60
        
        # Calculate cost and CO2
        cost = round(distance_km * self.cost_per_km, 2)
        co2 = round(distance_km * self.co2_per_km, 2)
        
        # Extract route geometry (polyline coordinates) - for map visualization
        geometry = []
        polyline = []  # Array of [lat, lon] for polyline drawing
        
        # TomTom API returns geometry in routes[0].legs[].points[]
        if legs:
            for leg in legs:
                points = leg.get('points', [])
                for point in points:
                    # TomTom uses 'latitude' and 'longitude' keys
                    lat = point.get('latitude') or point.get('lat')
                    lon = point.get('longitude') or point.get('lon')
                    if lat is not None and lon is not None:
                        geometry.append([float(lat), float(lon)])
                        polyline.append({'lat': float(lat), 'lon': float(lon)})
        
        # If no geometry from legs, try sections (alternative format)
        if not geometry and 'sections' in route:
            sections = route.get('sections', [])
            for section in sections:
                section_geometry = section.get('geometry', {})
                # Check if geometry is encoded polyline or coordinate list
                if 'coordinates' in section_geometry:
                    coords = section_geometry['coordinates']
                    for coord in coords:
                        if len(coord) >= 2:
                            lat, lon = float(coord[1]), float(coord[0])  # GeoJSON format [lon, lat]
                            geometry.append([lat, lon])
                            polyline.append({'lat': lat, 'lon': lon})
        
        # Extract turn-by-turn instructions
        instructions = []
        if legs:
            for leg in legs:
                for point in leg.get('points', []):
                    if 'instruction' in point:
                        instructions.append({
                            'instruction': point['instruction'],
                            'distance': point.get('routeOffsetInMeters', 0),
                            'time': point.get('travelTimeInSeconds', 0)
                        })
        
        return {
            'success': True,
            'route_type': route_type,
            'distance': f"{round(distance_km, 1)} km",
            'distance_km': round(distance_km, 2),
            'duration': f"{int(duration_minutes)} min",
            'duration_minutes': round(duration_minutes, 1),
            'duration_with_traffic': round(duration_minutes + traffic_delay, 1),
            'traffic_delay_minutes': round(traffic_delay, 1),
            'cost': f"${cost:.2f}",
            'cost_usd': cost,
            'co2_kg': co2,
            'fuel_consumption_liters': round(distance_km * 0.08, 2),
            'geometry': geometry,  # Array of [lat, lon] arrays
            'polyline': polyline,  # Array of {lat, lon} objects for easier frontend use
            'instructions': instructions[:10],
            'summary': {
                'departure_time': summary.get('departureTime'),
                'arrival_time': summary.get('arrivalTime')
            }
        }
    
    def _generate_comparison(self, fastest, cheapest, eco):
        """Generate comparison metrics between three routes"""
        # Check if all routes were successful
        successful_routes = []
        if fastest.get('success'):
            successful_routes.append(fastest)
        if cheapest.get('success'):
            successful_routes.append(cheapest)
        if eco.get('success'):
            successful_routes.append(eco)
        
        if len(successful_routes) < 2:
            return {
                'note': 'Not enough routes for comparison',
                'successful_routes': [r.get('route_type') for r in successful_routes],
                'recommendation': 'Use available routes for comparison'
            }
        
        # Find best in each category
        fastest_time = min(successful_routes, key=lambda x: x.get('duration_with_traffic', float('inf')))
        lowest_cost = min(successful_routes, key=lambda x: x.get('cost_usd', float('inf')))
        lowest_co2 = min(successful_routes, key=lambda x: x.get('co2_kg', float('inf')))
        
        comparison = {
            'fastest_route': fastest_time.get('route_type'),
            'cheapest_route': lowest_cost.get('route_type'),
            'greenest_route': lowest_co2.get('route_type'),
            'successful_routes': len(successful_routes)
        }
        
        # Add comparisons only if we have all three routes
        if fastest.get('success') and cheapest.get('success'):
            comparison['time_savings_fastest_vs_cheapest'] = round(
                cheapest.get('duration_with_traffic', 0) - fastest.get('duration_with_traffic', 0), 1
            )
        
        if fastest.get('success') and eco.get('success'):
            comparison['time_savings_fastest_vs_eco'] = round(
                eco.get('duration_with_traffic', 0) - fastest.get('duration_with_traffic', 0), 1
            )
        
        if fastest.get('success') and cheapest.get('success'):
            comparison['cost_savings_cheapest_vs_fastest'] = round(
                fastest.get('cost_usd', 0) - cheapest.get('cost_usd', 0), 2
            )
        
        comparison['recommendation'] = self._get_recommendation(fastest, cheapest, eco)
        
        return comparison
    
    def _get_recommendation(self, fastest, cheapest, eco):
        """Provide intelligent route recommendation"""
        successful_routes = []
        if fastest.get('success'):
            successful_routes.append(('fastest', fastest))
        if cheapest.get('success'):
            successful_routes.append(('cheapest', cheapest))
        if eco.get('success'):
            successful_routes.append(('eco', eco))
        
        if len(successful_routes) == 1:
            return f"Only {successful_routes[0][0]} route available"
        
        if len(successful_routes) == 0:
            return "No routes available"
        
        # Simple recommendation based on available routes
        if len(successful_routes) == 2:
            route1, route2 = successful_routes
            return f"Choose between {route1[0]} and {route2[0]} routes"
        
        # All three routes available
        time_diff = abs(fastest.get('duration_with_traffic', 0) - cheapest.get('duration_with_traffic', 0))
        cost_diff = abs(fastest.get('cost_usd', 0) - cheapest.get('cost_usd', 0))
        
        if time_diff < 5 and cost_diff > 2:
            return "Choose cheapest route - minimal time difference with significant cost savings"
        elif time_diff > 15:
            return "Choose fastest route if time is critical"
        elif eco.get('co2_kg', 0) < cheapest.get('co2_kg', 0) * 0.8:
            return "Choose eco-friendly route for significantly lower emissions"
        else:
            return "Routes are comparable - choose based on your priority"