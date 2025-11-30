import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Send, MapPin } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import ProtectedRoute from '../components/ProtectedRoute'
import MapComponent from '../components/MapComponent'
import MapFilters from '../components/MapFilters'
import { compareRoutes } from '../utils/api'
import './SmartRoutes.css'

const SmartRoutes = () => {
  const [origin, setOrigin] = useState('')
  const [destination, setDestination] = useState('')
  const [loading, setLoading] = useState(false)
  const [routes, setRoutes] = useState(null)
  const [error, setError] = useState('')
  const [selectedRoute, setSelectedRoute] = useState(null)
  const [mapFilters, setMapFilters] = useState({
    pois: false,
    traffic: false,
    quiet: false,
    publicTransport: false,
    walkFriendly: false,
    time: '12:00'
  })
  const { getAuthHeader } = useAuth()

  const handleFilterChange = (filterId, value) => {
    setMapFilters(prev => ({
      ...prev,
      [filterId]: value
    }))
  }

  const handleFindRoutes = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    setRoutes(null)

    try {
      const response = await compareRoutes(origin, destination)
      
      // Backend returns { success: true/false, data: {...}, error: ... }
      // Extract data from response
      const routeData = response.success ? (response.data || response) : response
      
      if (!routeData || (routeData.success === false)) {
        throw new Error(routeData?.error || 'Route calculation failed')
      }
      
      // Transform backend response to match our format
      const routeOptions = [
        {
          type: 'Fastest',
          id: 'fastest',
          time: routeData.fastest?.duration || `${Math.round(routeData.fastest?.duration_minutes || 0)} min`,
          distance: routeData.fastest?.distance || `${routeData.fastest?.distance_km || 0} km`,
          cost: routeData.fastest?.cost || `$${routeData.fastest?.cost_usd || 0}`,
          color: '#1E90FF', // Blue
          data: { ...routeData.fastest, origin: routeData.origin, destination: routeData.destination },
          polyline: routeData.fastest?.polyline || [],
          geometry: routeData.fastest?.geometry || [],
        },
        {
          type: 'Eco-Friendly',
          id: 'eco',
          time: routeData.eco?.duration || `${Math.round(routeData.eco?.duration_minutes || 0)} min`,
          distance: routeData.eco?.distance || `${routeData.eco?.distance_km || 0} km`,
          cost: routeData.eco?.cost || `$${routeData.eco?.cost_usd || 0}`,
          color: '#228B22', // Green
          data: { ...routeData.eco, origin: routeData.origin, destination: routeData.destination },
          polyline: routeData.eco?.polyline || [],
          geometry: routeData.eco?.geometry || [],
        },
        {
          type: 'Cost Efficient',
          id: 'cheapest',
          time: routeData.cheapest?.duration || `${Math.round(routeData.cheapest?.duration_minutes || 0)} min`,
          distance: routeData.cheapest?.distance || `${routeData.cheapest?.distance_km || 0} km`,
          cost: routeData.cheapest?.cost || `$${routeData.cheapest?.cost_usd || 0}`,
          color: '#FF8C00', // Orange
          data: { ...routeData.cheapest, origin: routeData.origin, destination: routeData.destination },
          polyline: routeData.cheapest?.polyline || [],
          geometry: routeData.cheapest?.geometry || [],
        },
      ].filter(route => route.data?.success !== false) // Filter out failed routes

      if (routeOptions.length === 0) {
        throw new Error('No routes found. Please check your origin and destination.')
      }

      setRoutes(routeOptions)
      setSelectedRoute(routeOptions[0])
    } catch (err) {
      setError(err.message || 'Failed to find routes. Please try again.')
      console.error('Route planning error:', err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <ProtectedRoute>
      <div className="smart-routes-page">
        <div className="container">
          <motion.div
            className="routes-header"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="page-title">
              <span className="title-part">Smart Route</span>{' '}
              <span className="title-part gradient">Planner</span>
            </h1>
            <p className="page-subtitle">Get optimized routes with AI-powered insights</p>
          </motion.div>

          <motion.div
            className="plan-journey-card"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
          >
            <div className="card-header">
              <Send size={24} className="card-icon" />
              <h2>Plan Your Journey</h2>
            </div>
            <p className="card-description">
              Enter your origin and destination to discover optimal routes
            </p>

            <form onSubmit={handleFindRoutes} className="route-form">
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="origin">Origin</label>
                  <input
                    type="text"
                    id="origin"
                    value={origin}
                    onChange={(e) => setOrigin(e.target.value)}
                    placeholder="e.g., Delhi, Times Square, Mumbai"
                    required
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="destination">Destination</label>
                  <input
                    type="text"
                    id="destination"
                    value={destination}
                    onChange={(e) => setDestination(e.target.value)}
                    placeholder="e.g., Mumbai, Connaught Place, Noida"
                    required
                  />
                </div>
              </div>

              {error && <div className="error-message">{error}</div>}

              <motion.button
                type="submit"
                className="find-routes-button"
                disabled={loading}
                whileHover={{ scale: loading ? 1 : 1.02 }}
                whileTap={{ scale: loading ? 1 : 0.98 }}
              >
                {loading ? 'Finding Routes...' : 'Find Routes'}
              </motion.button>
            </form>
          </motion.div>

          {routes && (
            <motion.div
              className="routes-results"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              <div className="results-grid">
                <div className="map-panel">
                  <div className="map-wrapper">
                    <MapFilters
                      filters={mapFilters}
                      onFilterChange={handleFilterChange}
                      className="map-filters-overlay"
                    />
                    <MapComponent
                      routes={routes}
                      selectedRouteId={selectedRoute?.id}
                      origin={routes?.[0]?.data?.origin}
                      destination={routes?.[0]?.data?.destination}
                      className="route-map"
                    />
                  </div>
                </div>

                <div className="routes-comparison">
                  <h3>Route Comparison</h3>
                  <div className="route-bars">
                    {routes.map((route, index) => (
                      <motion.div
                        key={route.type}
                        className={`route-bar ${selectedRoute?.type === route.type ? 'active' : ''}`}
                        initial={{ width: 0 }}
                        animate={{ width: '100%' }}
                        transition={{ duration: 0.8, delay: index * 0.1 }}
                        onClick={() => {
                          setSelectedRoute(route)
                          // Scroll map into view if needed
                        }}
                        style={{ '--route-color': route.color }}
                      >
                        <div className="route-bar-content">
                          <div className="route-bar-header">
                            <span className="route-type">{route.type}</span>
                            <span className="route-time">{route.time}</span>
                          </div>
                          <div className="route-bar-fill" style={{ backgroundColor: route.color }}></div>
                          <div className="route-bar-details">
                            <span>{route.distance}</span>
                            <span>{route.cost}</span>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  )
}

export default SmartRoutes

