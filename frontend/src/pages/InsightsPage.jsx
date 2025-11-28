import React from 'react'
import { motion } from 'framer-motion'
import MapComponent from '../components/MapComponent'
import BusiestHoursChart from '../components/BusiestHoursChart'
import './InsightsPage.css'

const InsightsPage = () => {
  return (
    <motion.div
      className="insights-page"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <h1>Traffic Insights</h1>
      <p className="subtitle">Analyze location-based data and mobility patterns</p>
      
      <div className="insights-grid">
        <div className="insight-card">
          <h2>Traffic Heatmap</h2>
          <MapComponent />
        </div>
        
        <div className="insight-card">
          <BusiestHoursChart />
        </div>
        
        <div className="insight-card">
          <h2>POI Analysis</h2>
          <p>Points of Interest analysis coming soon...</p>
        </div>
        
        <div className="insight-card">
          <h2>Mobility Patterns</h2>
          <p>Mobility pattern analysis coming soon...</p>
        </div>
      </div>
    </motion.div>
  )
}

export default InsightsPage

