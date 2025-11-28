import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Send, MapPin } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import ProtectedRoute from '../components/ProtectedRoute'
import { compareRoutes } from '../utils/api'
import './SmartRoutes.css'

const SmartRoutes = () => {
  const [origin, setOrigin] = useState('')
  const [destination, setDestination] = useState('')
  const [loading, setLoading] = useState(false)
  const [routes, setRoutes] = useState(null)
  const [error, setError] = useState('')
  const [selectedRoute, setSelectedRoute] = useState(null)
  const { getAuthHeader } = useAuth()

  const handleFindRoutes = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    setRoutes(null)

    try {
      const result = await compareRoutes(origin, destination)
      
      // Transform backend response to match our format
      const routeOptions = [
        {
          type: 'Fastest',
          time: result.fastest?.duration || '25 min',
          distance: result.fastest?.distance || '12.5 km',
          cost: result.fastest?.cost || '$5.20',
          color: '#2196f3',
          data: result.fastest,
        },
        {
          type: 'Eco-Friendly',
          time: result.eco?.duration || '30 min',
          distance: result.eco?.distance || '13.2 km',
          cost: result.eco?.cost || '$4.80',
          color: '#4caf50',
          data: result.eco,
        },
        {
          type: 'Cost Efficient',
          time: result.cheapest?.duration || '28 min',
          distance: result.cheapest?.distance || '12.8 km',
          cost: result.cheapest?.cost || '$4.50',
          color: '#ff9800',
          data: result.cheapest,
        },
      ]

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
                    placeholder="e.g., Downtown Station"
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
                    placeholder="e.g., City Airport"
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
                  <div className="map-container">
                    <div className="map-visualization">
                      <div className="map-route-line-animated"></div>
                      <div className="map-pin map-pin-start">
                        <MapPin size={20} />
                      </div>
                      <div className="map-pin map-pin-end">
                        <MapPin size={20} />
                      </div>
                    </div>
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
                        onClick={() => setSelectedRoute(route)}
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

