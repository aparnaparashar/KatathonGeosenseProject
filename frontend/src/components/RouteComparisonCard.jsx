import React from 'react'
import { motion } from 'framer-motion'
import { Clock, DollarSign, Leaf } from 'lucide-react'
import './RouteComparisonCard.css'

const RouteComparisonCard = ({ routes = [] }) => {
  const routeTypes = [
    { type: 'fastest', icon: Clock, label: 'Fastest', color: '#3b82f6' },
    { type: 'cheapest', icon: DollarSign, label: 'Cheapest', color: '#10b981' },
    { type: 'eco-friendly', icon: Leaf, label: 'Eco-Friendly', color: '#22c55e' }
  ]

  return (
    <div className="route-comparison">
      <h2>Route Comparison</h2>
      <div className="route-cards">
        {routeTypes.map((routeType, index) => {
          const Icon = routeType.icon
          const route = routes.find(r => r.type === routeType.type) || {}
          
          return (
            <motion.div
              key={routeType.type}
              className="route-card"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ scale: 1.05 }}
            >
              <div className="route-header" style={{ borderColor: routeType.color }}>
                <Icon size={24} color={routeType.color} />
                <h3>{routeType.label}</h3>
              </div>
              <div className="route-details">
                <div className="detail-item">
                  <span>Distance:</span>
                  <strong>{route.distance || 'N/A'} km</strong>
                </div>
                <div className="detail-item">
                  <span>Duration:</span>
                  <strong>{route.duration || 'N/A'} min</strong>
                </div>
                {routeType.type === 'cheapest' && (
                  <div className="detail-item">
                    <span>Cost:</span>
                    <strong>${route.cost || 'N/A'}</strong>
                  </div>
                )}
                {routeType.type === 'eco-friendly' && (
                  <div className="detail-item">
                    <span>CO₂:</span>
                    <strong>{route.carbon || 'N/A'} kg</strong>
                  </div>
                )}
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

export default RouteComparisonCard

