import React, { useState } from 'react'
import { motion } from 'framer-motion'
import MapComponent from '../components/MapComponent'
import RouteComparisonCard from '../components/RouteComparisonCard'
import './RoutesPage.css'

const RoutesPage = () => {
  const [origin, setOrigin] = useState('')
  const [destination, setDestination] = useState('')
  const [routes, setRoutes] = useState([])

  const handleCompareRoutes = async () => {
    // TODO: Implement API call to compare routes
    console.log('Comparing routes...')
  }

  return (
    <motion.div
      className="routes-page"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <h1>Route Comparison</h1>
      <p className="subtitle">Compare fastest, cheapest, and eco-friendly routes</p>
      
      <div className="route-input-section">
        <div className="input-group">
          <label>Origin</label>
          <input
            type="text"
            value={origin}
            onChange={(e) => setOrigin(e.target.value)}
            placeholder="Enter origin address"
          />
        </div>
        <div className="input-group">
          <label>Destination</label>
          <input
            type="text"
            value={destination}
            onChange={(e) => setDestination(e.target.value)}
            placeholder="Enter destination address"
          />
        </div>
        <button onClick={handleCompareRoutes} className="compare-button">
          Compare Routes
        </button>
      </div>
      
      <RouteComparisonCard routes={routes} />
      
      <div className="map-section">
        <h2>Route Visualization</h2>
        <MapComponent />
      </div>
    </motion.div>
  )
}

export default RoutesPage

