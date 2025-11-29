from flask import Blueprint, request, jsonify, current_app
import re
import requests
import os
import time

# Simple in-memory cache for POIs and assistant responses to improve responsiveness
POI_CACHE = {}
POI_CACHE_TTL = 60 * 10  # 10 minutes

# Cache assistant replies (message+coords) to avoid repeated LLM calls
ASSISTANT_CACHE = {}
ASSISTANT_CACHE_TTL = 60 * 60  # 1 hour

try:
    import openai
except Exception:
    openai = None

chat_bp = Blueprint('chat', __name__)

# key helpers

def _cache_key_for_coords(lat, lng, precision=3):
    # quantize coordinates so nearby requests hit the same cache
    return f"{round(lat, precision)}:{round(lng, precision)}"


def geocode_destination(query, tomtom_key):
    """Geocode a free-form query to lat/lon using TomTom Geocoding API."""
    try:
        url = f"https://api.tomtom.com/search/2/geocode/{requests.utils.requote_uri(query)}.json"
        # Bias geocoding results to India to avoid US defaults when ambiguous
        params = {'key': tomtom_key, 'limit': 1, 'countrySet': 'IN'}
        resp = requests.get(url, params=params, timeout=8)
        if resp.ok:
            j = resp.json()
            results = j.get('results') or []
            if results:
                pos = results[0].get('position') or {}
                return {'lat': pos.get('lat'), 'lng': pos.get('lon')}
    except Exception:
        current_app.logger.exception('TomTom geocode failed')
    return None


def tomtom_poi_search(lat, lng, tomtom_key, limit=6):
    """Search for attractive POIs around lat/lng using a set of tourist-oriented queries and return unique results."""
    if not tomtom_key:
        return []
    # Cache lookup: quantize coords to reduce cardinality
    cache_key = _cache_key_for_coords(lat, lng, precision=3)
    now = time.time()
    cached = POI_CACHE.get(cache_key)
    if cached and now - cached.get('ts', 0) < POI_CACHE_TTL:
        return cached.get('pois', [])[:limit]

    # Use a smaller, focused set of keywords for speed and relevance
    keywords = ['park', 'viewpoint', 'museum', 'landmark']
    pois = []
    seen = set()
    for kw in keywords:
        try:
            url = f"https://api.tomtom.com/search/2/poiSearch/{requests.utils.requote_uri(kw)}.json"
            # smaller radius and shorter timeout to keep requests snappy
            # Bias POI search to India (useful when coordinates near border or ambiguous)
            params = {'key': tomtom_key, 'lat': lat, 'lon': lng, 'limit': limit, 'radius': 2000, 'countrySet': 'IN'}
            resp = requests.get(url, params=params, timeout=4)
            if not resp.ok:
                continue
            j = resp.json()
            results = j.get('results') or j.get('pois') or []
            for r in results:
                # TomTom returns different shapes; try common keys
                name = None
                if isinstance(r.get('poi', {}), dict):
                    name = r.get('poi', {}).get('name')
                name = name or r.get('name') or (r.get('address') or {}).get('freeformAddress')
                pos = r.get('position') or {'lat': r.get('lat'), 'lon': r.get('lon')}
                if not name or not pos:
                    continue
                key = f"{name}|{pos.get('lat')}|{pos.get('lon')}"
                if key in seen:
                    continue
                seen.add(key)
                pois.append({
                    'name': name,
                    'category': r.get('poi', {}).get('categories', []) if r.get('poi') else [],
                    'position': {'lat': pos.get('lat'), 'lng': pos.get('lon')}
                })
                if len(pois) >= limit:
                    # cache and return
                    POI_CACHE[cache_key] = {'ts': now, 'pois': pois}
                    return pois
        except Exception:
            current_app.logger.exception('TomTom POI search failed for keyword %s', kw)
            continue
    # cache results before returning
    POI_CACHE[cache_key] = {'ts': now, 'pois': pois}
    return pois

    # store handled below (note: unreachable here if returned earlier)


def call_openai(system_prompt, user_message, nearby_pois, openai_key):
    # OpenAI removed for TomTom-only chatbot. This function intentionally left blank.
    return None


def call_gemini(system_prompt, user_message, nearby_pois, gemini_key):
    """Call Google Generative API (Gemini) via simple API-key endpoint if available.
    This uses the public REST generateText endpoint and expects the API key to be enabled for Generative API.
    If not configured, this will return None.
    """
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta2/models/text-bison-001:generateText?key={gemini_key}"
        prompt_text = system_prompt + "\nNearby POIs: " + str(nearby_pois) + "\nUser: " + user_message
        body = {
            'prompt': {'text': prompt_text},
            'temperature': 0.6,
            'maxOutputTokens': 600
        }
        resp = requests.post(url, json=body, timeout=12)
        if resp.ok:
            j = resp.json()
            candidates = j.get('candidates') or []
            if candidates:
                return candidates[0].get('content')
    except Exception:
        current_app.logger.exception('Gemini call failed')
    return None


# ----------------------------
# TomTom helper functions (search, geocode, reverse, routing, traffic, autocomplete)
# ----------------------------

def _tomtom_key():
    return current_app.config.get('TOMTOM_API_KEY')


def search_place(query, tomtom_key):
    if not tomtom_key or not query:
        return None
    try:
        url = f"https://api.tomtom.com/search/2/search/{requests.utils.requote_uri(query)}.json"
        # Bias search to India to return Indian results for ambiguous place names
        params = {'key': tomtom_key, 'limit': 1, 'countrySet': 'IN'}
        resp = requests.get(url, params=params, timeout=4)
        if resp.ok:
            j = resp.json()
            results = j.get('results') or []
            if results:
                return results[0]
    except Exception:
        current_app.logger.exception('TomTom search failed for %s', query)
    return None


def autocomplete_place(prefix, tomtom_key, limit=5):
    if not tomtom_key or not prefix:
        return []
    try:
        url = f"https://api.tomtom.com/search/2/autocomplete/{requests.utils.requote_uri(prefix)}.json"
        # Bias autocomplete to India
        params = {'key': tomtom_key, 'limit': limit, 'countrySet': 'IN'}
        resp = requests.get(url, params=params, timeout=3)
        if resp.ok:
            j = resp.json()
            return j.get('results') or []
    except Exception:
        current_app.logger.exception('TomTom autocomplete failed for %s', prefix)
    return []


def reverse_geocode(lat, lng, tomtom_key):
    if not tomtom_key:
        return None
    try:
        url = f"https://api.tomtom.com/search/2/reverseGeocode/{lat},{lng}.json"
        params = {'key': tomtom_key, 'limit': 1}
        resp = requests.get(url, params=params, timeout=4)
        if resp.ok:
            j = resp.json()
            results = j.get('addresses') or j.get('results') or []
            if results:
                addr = results[0]
                # TomTom returns address object in different keys; try common ones
                freeform = addr.get('address', {}).get('freeformAddress') or addr.get('address', {})
                return freeform
    except Exception:
        current_app.logger.exception('TomTom reverse geocode failed')
    return None


def get_route(slat, slon, dlat, dlon, tomtom_key):
    if not tomtom_key:
        return None
    try:
        url = f"https://api.tomtom.com/routing/1/calculateRoute/{slat},{slon}:{dlat},{dlon}/json"
        params = {'key': tomtom_key, 'routeType': 'fast', 'language': 'en-US', 'computeTravelTimeFor': 'all'}
        resp = requests.get(url, params=params, timeout=6)
        if resp.ok:
            return resp.json()
    except Exception:
        current_app.logger.exception('TomTom routing failed')
    return None


def nearby_search(lat, lng, query, tomtom_key, limit=6):
    if not tomtom_key:
        return []
    try:
        url = f"https://api.tomtom.com/search/2/nearbySearch/.json"
        # nearby search anchored to provided coords; also restrict to India
        params = {'key': tomtom_key, 'lat': lat, 'lon': lng, 'query': query, 'limit': limit, 'countrySet': 'IN'}
        resp = requests.get(url, params=params, timeout=4)
        if resp.ok:
            j = resp.json()
            return j.get('results') or []
    except Exception:
        current_app.logger.exception('TomTom nearby search failed')
    return []


def traffic_info(lat, lng, tomtom_key):
    # Use TomTom Flow Segment Data for a quick traffic snapshot
    if not tomtom_key:
        return None
    try:
        url = f"https://api.tomtom.com/traffic/services/4/flowSegmentData/absolute/10/json"
        params = {'point': f"{lat},{lng}", 'unit': 'KMPH', 'key': tomtom_key}
        resp = requests.get(url, params=params, timeout=4)
        if resp.ok:
            j = resp.json()
            flow = j.get('flowSegmentData') or {}
            return flow
    except Exception:
        current_app.logger.exception('TomTom traffic call failed')
    return None


@chat_bp.route('/', methods=['POST'])
def chat():
    """Handle chatbot requests. Expects JSON { message: str, destination: {lat, lng} or destination: 'place name' (optional) }"""
    data = request.get_json() or {}
    message = (data.get('message') or '').strip()
    destination = data.get('destination')  # could be dict or string

    if not message:
        return jsonify({'error': 'Message is required'}), 400

    tomtom_key = current_app.config.get('TOMTOM_API_KEY')
    openai_key = current_app.config.get('OPENAI_API_KEY')
    gemini_key = current_app.config.get('GEMINI_API_KEY')

    pois = []

    # Resolve destination to coordinates if provided as string
    coords = None
    if isinstance(destination, str) and tomtom_key:
        coords = geocode_destination(destination, tomtom_key)
    elif isinstance(destination, dict):
        lat = destination.get('lat') or destination.get('latitude')
        lng = destination.get('lng') or destination.get('lon') or destination.get('longitude')
        if lat is not None and lng is not None:
            coords = {'lat': lat, 'lng': lng}

    # If we have coordinates, fetch nearby POIs
    if coords and tomtom_key:
        pois = tomtom_poi_search(coords['lat'], coords['lng'], tomtom_key, limit=6)

    # System prompt guiding behavior — be conversational, ask clarifying questions, and include geography/history
    system_prompt = (
        "You are GeoSense Assistant — a friendly, conversational travel and routing assistant. "
        "Speak kindly and clearly, ask concise clarifying questions when user intent or location is ambiguous, and give practical, actionable advice. "
        "When recommending places include a brief safety tip, routing considerations (construction, traffic, VIP or ambulance priorities), and a short historical or geographic fact when relevant. "
        "Occasionally include a short 'Did you know?' fact to make the suggestions engaging. Keep responses helpful, empathetic, and concise (aim for 3-6 sentences unless user asks for more)."
    )

    # Lightweight intent detection: if the user asks to reach somewhere or requests safest routes
    travel_intents = ['reach', 'get to', 'safest', 'safe route', 'route', 'reach here', 'reach there', 'how to get', 'need to reach', 'need to get']
    safety_keywords = ['safe', 'safety', 'rain', 'flood', 'construction', 'blocked', 'ambulance', 'vip']
    text_lower = message.lower()
    wants_travel = any(tok in text_lower for tok in travel_intents)
    mentions_safety = any(tok in text_lower for tok in safety_keywords)

    # If user clearly wants routing advice but no coordinates/destination provided, ask a clarifying question
    if wants_travel and not coords:
        # Ask only for the minimal information to proceed
        clarifying = "Can you share the destination (place name or address) and whether you'll be driving, walking, or taking public transport?"
        # If the user mentioned safety concerns (rain, ambulance), include that in the clarifying prompt
        if mentions_safety:
            clarifying = (
                "I can help you find the safest route — could you give me the destination (place name or address) and your mode of travel? "
                "Also tell me if you need ambulance-aware routing or want to avoid flooded/under-construction roads."
            )
        return jsonify({'assistant': clarifying, 'nearby_pois': pois, 'coords': coords}), 200

    assistant_text = None

    # Check assistant cache to avoid repeated LLM calls for same message+coords
    try:
        cache_coords_part = _cache_key_for_coords(coords['lat'], coords['lng']) if coords else 'no_coords'
    except Exception:
        cache_coords_part = 'no_coords'
    assistant_cache_key = f"{message}|{cache_coords_part}"
    cached_assistant = ASSISTANT_CACHE.get(assistant_cache_key)
    if cached_assistant and time.time() - cached_assistant.get('ts', 0) < ASSISTANT_CACHE_TTL:
        return jsonify({'assistant': cached_assistant.get('text'), 'nearby_pois': pois, 'coords': coords}), 200

    # ----------------------------
    # TomTom-only intent handling (no LLM)
    # ----------------------------
    tomtom_key = _tomtom_key()

    # helper to respond and cache
    def respond(text, extra=None):
        try:
            ASSISTANT_CACHE[assistant_cache_key] = {'ts': time.time(), 'text': text}
        except Exception:
            current_app.logger.exception('Failed to write assistant cache')
        payload = {'assistant': text, 'nearby_pois': pois, 'coords': coords}
        if extra:
            payload.update(extra)
        return jsonify(payload), 200

    text_lower = message.lower()

    # 1) Route / Distance intent
    if any(k in text_lower for k in ['route', 'distance', 'how to go', 'how do i get', 'directions']):
        # try to parse "from A to B"
        try:
            if ' from ' in text_lower and ' to ' in text_lower:
                parts = message.split(' from ', 1)[1]
                src_raw, dst_raw = parts.split(' to ', 1)
                src, dst = src_raw.strip(), dst_raw.strip()
            elif text_lower.startswith('route to ') or text_lower.startswith('directions to '):
                # assume origin is provided in destination payload or ask
                dst = message.split(' to ', 1)[1].strip()
                src = None
            else:
                return respond("Please ask like: 'Route from Delhi to Agra' or provide a destination and your origin.")

            # resolve places
            src_place = search_place(src, tomtom_key) if src else None
            dst_place = search_place(dst, tomtom_key) if dst else None

            if not dst_place:
                return respond("I couldn't find the destination. Please provide a clearer place name or address.")

            if src and not src_place:
                return respond("I couldn't find the source location. Please check the source name.")

            # if origin not provided, try coords from payload
            if not src_place and coords:
                src_place = {'position': {'lat': coords['lat'], 'lon': coords['lng']}}

            slat = src_place['position']['lat'] if src_place else None
            slon = src_place['position']['lon'] if src_place else None
            dlat = dst_place['position']['lat']
            dlon = dst_place['position']['lon']

            if slat is None or slon is None:
                return respond("Please provide the starting location or say 'from <place> to <place>'.")

            route = get_route(slat, slon, dlat, dlon, tomtom_key)
            if not route:
                return respond("Couldn't compute a route right now. Try again later.")

            summary = route.get('routes', [])[0].get('summary', {})
            dist_km = summary.get('lengthInMeters', 0) / 1000.0
            time_min = summary.get('travelTimeInSeconds', 0) / 60.0
            reply = f"Distance from {src or 'your location'} to {dst} is {dist_km:.2f} km, estimated time {time_min:.1f} minutes."
            return respond(reply, extra={'route': route})

        except Exception:
            current_app.logger.exception('Failed to handle route intent')
            return respond("Please ask like: 'Route from Delhi to Agra' or include both source and destination.")

    # 2) Nearby search intent
    if 'near me' in text_lower or 'nearby' in text_lower or 'near ' in text_lower:
        # prefer coords from payload, then destination string, then ask
        q = text_lower.replace('near me', '').replace('nearby', '').replace('near', '').strip()
        if not q:
            q = 'restaurant'
        center = None
        if coords:
            center = coords
        elif isinstance(destination, str) and tomtom_key:
            center = geocode_destination(destination, tomtom_key)

        if not center:
            return respond('Please provide a location or allow sharing coordinates for nearby search.')

        results = nearby_search(center['lat'], center['lng'], q, tomtom_key, limit=6)
        if not results:
            return respond(f'No nearby {q} found.')
        names = [r.get('poi', {}).get('name') or r.get('name') for r in results[:6]]
        return respond(f'Nearby {q}: ' + ', '.join([n for n in names if n]))

    # 3) Reverse geocoding / coordinates -> address
    coord_match = re.search(r'(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)', message)
    if 'address' in text_lower or 'what is at' in text_lower or coord_match:
        if coord_match:
            lat_s, lon_s = coord_match.groups()
            addr = reverse_geocode(lat_s, lon_s, tomtom_key)
            if addr:
                return respond(f'Address: {addr}')
            return respond('No address found for those coordinates.')
        # if no coords, but destination provided as string
        if isinstance(destination, dict) and destination.get('lat') and destination.get('lng'):
            addr = reverse_geocode(destination['lat'], destination['lng'], tomtom_key)
            if addr:
                return respond(f'Address: {addr}')
        return respond('Please provide coordinates like "12.34,56.78" to reverse geocode or specify a place.')

    # 4) Autocomplete / city search
    if any(k in text_lower for k in ['autocomplete', 'suggest', 'search ', 'find ']):
        # extract a short query
        q = message.replace('autocomplete', '').replace('suggest', '').replace('search', '').replace('find', '').strip()
        if not q:
            return respond('Please provide a search prefix to autocomplete.')
        candidates = autocomplete_place(q, tomtom_key, limit=6)
        names = [c.get('address', {}).get('freeformAddress') or c.get('poi', {}).get('name') or c.get('address') or c.get('type') for c in candidates[:6]]
        names = [n for n in names if n]
        if not names:
            return respond('No suggestions found.')
        return respond('Suggestions: ' + ', '.join(names))

    # 5) Traffic info
    if 'traffic' in text_lower:
        center = None
        if coords:
            center = coords
        elif isinstance(destination, str) and tomtom_key:
            center = geocode_destination(destination, tomtom_key)
        if not center:
            return respond('Please provide coordinates or a destination to check traffic.')
        flow = traffic_info(center['lat'], center['lng'], tomtom_key)
        if not flow:
            return respond('No traffic data available for this location.')
        current_speed = flow.get('currentSpeed')
        free_flow = flow.get('freeFlowSpeed')
        confidence = flow.get('confidenceLevel')
        reply = f"Traffic: current speed {current_speed} km/h, free flow {free_flow} km/h, confidence {confidence}."
        return respond(reply, extra={'traffic': flow})

    # Default help response
    help_text = (
        "Hi, I’m your city travel assistant! I suggest smarter routes for every need — from emergency paths like ambulance priority roads, "
        "VIP or low-traffic corridors, to everyday finds like nearby restaurants, hospitals, parks, and other popular places. "
        "I also share real-time route options including the fastest and least congested choices, and highlight multiple paths directly on your map. "
        "Think of me as your traffic navigator and city guide combined — here to make your trips quicker and easier. "
        "Just tell me what you’re looking for, and I’ll point you the right way!"
    )
    return respond(help_text)
