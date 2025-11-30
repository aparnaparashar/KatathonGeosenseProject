import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Filter, MapPin, TrendingUp, Leaf, Bus, User } from 'lucide-react'
import './MapFilters.css'

const MapFilters = ({ filters, onFilterChange, className = '' }) => {
  const [isOpen, setIsOpen] = useState(false)

  const filterOptions = [
    { id: 'pois', label: 'Points of Interest', icon: MapPin, description: 'Malls, hospitals, metro stations' },
    { id: 'traffic', label: 'Traffic Heatmap', icon: TrendingUp, description: 'Congestion density overlay' },
    { id: 'quiet', label: 'Quiet Zones', icon: Leaf, description: 'Low traffic areas' },
    { id: 'publicTransport', label: 'Public Transport', icon: Bus, description: 'Bus/metro stops' },
    { id: 'walkFriendly', label: 'Walk Friendly', icon: User, description: 'Sidewalks and parks' },
  ]

  return (
    <div className={`map-filters-container ${className}`}>
      <motion.button
        className="filter-toggle-btn"
        onClick={() => setIsOpen(!isOpen)}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
      >
        <Filter size={20} />
        <span>Filters</span>
      </motion.button>

      {isOpen && (
        <motion.div
          className="filter-panel"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
        >
          <h3 className="filter-panel-title">Map Filters</h3>
          
          <div className="filter-list">
            {filterOptions.map((option) => {
              const Icon = option.icon
              const isActive = filters[option.id] || false
              
              return (
                <motion.div
                  key={option.id}
                  className={`filter-item ${isActive ? 'active' : ''}`}
                  onClick={() => onFilterChange(option.id, !isActive)}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <div className="filter-checkbox">
                    <input
                      type="checkbox"
                      checked={isActive}
                      onChange={() => {}}
                      id={`filter-${option.id}`}
                    />
                    <label htmlFor={`filter-${option.id}`}>
                      <Icon size={18} />
                      <div className="filter-label-content">
                        <span className="filter-label">{option.label}</span>
                        <span className="filter-description">{option.description}</span>
                      </div>
                    </label>
                  </div>
                </motion.div>
              )
            })}
          </div>

          <div className="filter-time-section">
            <label htmlFor="time-filter">Time Filter</label>
            <input
              type="time"
              id="time-filter"
              value={filters.time || '12:00'}
              onChange={(e) => onFilterChange('time', e.target.value)}
              className="time-input"
            />
          </div>

          <button
            className="clear-filters-btn"
            onClick={() => {
              filterOptions.forEach(opt => onFilterChange(opt.id, false))
              onFilterChange('time', '12:00')
            }}
          >
            Clear All
          </button>
        </motion.div>
      )}
    </div>
  )
}

export default MapFilters

