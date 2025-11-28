import React from 'react'
import { Link } from 'react-router-dom'
import './GeoSenseLogo.css'

const GeoSenseLogo = ({ className = '' }) => {
  return (
    <Link to="/" className={`geosense-logo ${className}`}>
      <div className="logo-icon-wrapper">
        <svg viewBox="0 0 100 100" className="logo-icon-svg">
          <circle cx="50" cy="50" r="45" fill="#1a237e" />
          <path
            d="M 20 50 Q 50 20, 80 50 Q 50 80, 20 50"
            stroke="#4caf50"
            strokeWidth="4"
            fill="none"
            strokeLinecap="round"
          />
          <path
            d="M 50 20 L 60 50 L 50 70 L 40 50 Z"
            fill="none"
            stroke="#ffffff"
            strokeWidth="3"
            strokeLinejoin="round"
          />
        </svg>
      </div>
      <span className="logo-text">
        <span className="logo-geo">Geo</span>
        <span className="logo-sense">Sense</span>
      </span>
    </Link>
  )
}

export default GeoSenseLogo

