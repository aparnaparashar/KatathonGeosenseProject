/**
 * API utility functions for GeoSense frontend
 * Connects to Flask backend at localhost:5000
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

/**
 * Generic fetch wrapper with error handling
 * Supports JWT authentication via headers
 */
async function fetchAPI(endpoint, options = {}) {
  try {
    // Get JWT token from localStorage if available
    const token = localStorage.getItem('geosense_token')
    const headers = {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      headers,
      ...options,
    });

    if (!response.ok) {
      // If unauthorized, clear token and redirect to sign in
      if (response.status === 401) {
        localStorage.removeItem('geosense_token')
        localStorage.removeItem('geosense_user')
        window.location.href = '/signin'
      }
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error(`API Error (${endpoint}):`, error);
    throw error;
  }
}

/**
 * Geocode a location name to coordinates using TomTom
 */
export async function geocodeLocation(locationName) {
  try {
    // For now, return default Delhi coordinates
    // In production, implement proper geocoding
    const defaultLocations = {
      'india gate': { lat: 28.6139, lon: 77.2090 },
      'mumbai': { lat: 19.0760, lon: 72.8777 },
      'connaught place': { lat: 28.6304, lon: 77.2177 },
      'noida': { lat: 28.5355, lon: 77.3910 },
    };

    const normalized = locationName.toLowerCase().trim();
    return defaultLocations[normalized] || { lat: 28.6139, lon: 77.2090 };
  } catch (error) {
    console.error('Geocoding error:', error);
    return { lat: 28.6139, lon: 77.2090 }; // Default to India Gate
  }
}

/**
 * Compare three route types (fastest, cheapest, eco-friendly)
 */
export async function compareRoutes(origin, destination) {
  return fetchAPI('/api/routing/compare', {
    method: 'POST',
    body: JSON.stringify({ origin, destination }),
  });
}

/**
 * Get fastest route
 */
export async function getFastestRoute(origin, destination) {
  return fetchAPI('/api/routing/fastest', {
    method: 'POST',
    body: JSON.stringify({ origin, destination }),
  });
}

/**
 * Get cheapest route
 */
export async function getCheapestRoute(origin, destination) {
  return fetchAPI('/api/routing/cheapest', {
    method: 'POST',
    body: JSON.stringify({ origin, destination }),
  });
}

/**
 * Get eco-friendly route
 */
export async function getEcoRoute(origin, destination) {
  return fetchAPI('/api/routing/eco-friendly', {
    method: 'POST',
    body: JSON.stringify({ origin, destination }),
  });
}

/**
 * Get traffic insights for a location
 */
export async function getTrafficInsights(lat, lon) {
  return fetchAPI(`/api/insights/traffic?lat=${lat}&lon=${lon}`);
}

/**
 * Get busiest hours for a location
 */
export async function getBusiestHours(lat, lon) {
  return fetchAPI(`/api/insights/busiest-hours?lat=${lat}&lon=${lon}`);
}

/**
 * Get POI analysis
 */
export async function getPOIAnalysis(lat, lon, radius = 5000) {
  return fetchAPI(`/api/insights/poi-analysis?lat=${lat}&lon=${lon}&radius=${radius}`);
}

/**
 * Get mobility patterns
 */
export async function getMobilityPatterns(lat, lon) {
  return fetchAPI(`/api/insights/mobility-patterns?lat=${lat}&lon=${lon}`);
}

/**
 * Generate PDF report
 */
export async function generatePDFReport(stakeholder, reportType, data) {
  return fetchAPI('/api/reports/pdf', {
    method: 'POST',
    body: JSON.stringify({ stakeholder, report_type: reportType, data }),
  });
}

/**
 * Generate CSV report
 */
export async function generateCSVReport(reportType, data) {
  return fetchAPI('/api/reports/csv', {
    method: 'POST',
    body: JSON.stringify({ report_type: reportType, data }),
  });
}

/**
 * Download a generated report
 */
export function downloadReport(filename) {
  window.open(`${API_BASE_URL}/api/reports/download/${filename}`, '_blank');
}

/**
 * List all available reports
 */
export async function listReports() {
  return fetchAPI('/api/reports/list');
}

/**
 * Health check
 */
export async function healthCheck() {
  return fetchAPI('/api/health');
}

export default {
  compareRoutes,
  getFastestRoute,
  getCheapestRoute,
  getEcoRoute,
  getTrafficInsights,
  getBusiestHours,
  getPOIAnalysis,
  getMobilityPatterns,
  generatePDFReport,
  generateCSVReport,
  downloadReport,
  listReports,
  healthCheck,
  geocodeLocation,
};