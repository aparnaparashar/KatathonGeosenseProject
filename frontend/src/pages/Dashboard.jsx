import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import ProtectedRoute from '../components/ProtectedRoute'
import MapComponent from '../components/MapComponent'
import { Leaf, MapPin, Zap, TrendingUp, Users, Clock, AlertTriangle } from 'lucide-react'
import { 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  LineChart,
  Line,
  Area,
  AreaChart
} from 'recharts'
import './Dashboard.css'

const Dashboard = () => {
  const { getAuthHeader } = useAuth()
  const [dashboardData, setDashboardData] = useState({
    sustainability: {
      ecoRoutes: 0,
      co2Saved: 0,
      sustainabilityScore: 0,
    },
    location: {
      lat: 27.1573,
      lng: 77.9620,
    },
    stats: {
      activeRoutes: 1214,
      activeRoutesChange: 12.5,
      currentCongestion: 59,
      modelaccuracy: 80,
      peakHour: '6-8 PM',
      peakCongestion: 95,
    },
    recentRoutes: [],
  })
  const [loading, setLoading] = useState(true)
  const [currentLocation, setCurrentLocation] = useState(null)
  const [locationError, setLocationError] = useState(null)
  const [locationLoading, setLocationLoading] = useState(true)

  useEffect(() => {
    fetchDashboardData()
    // Poll every 5 seconds
    const interval = setInterval(fetchDashboardData, 5000)
    return () => clearInterval(interval)
  }, [])

  // Get user's current location using browser geolocation API
  useEffect(() => {
    if ('geolocation' in navigator) {
      setLocationLoading(true)
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords
          setCurrentLocation({
            lat: latitude,
            lon: longitude,
          })
          // Update dashboardData location as well for backward compatibility
          setDashboardData((prev) => ({
            ...prev,
            location: {
              lat: latitude,
              lng: longitude,
            },
          }))
          setLocationLoading(false)
          setLocationError(null)
        },
        (error) => {
          console.error('Geolocation error:', error)
          setLocationError(error.message)
          setLocationLoading(false)
          // Keep default location if geolocation fails
          setCurrentLocation({
            lat: dashboardData.location.lat,
            lon: dashboardData.location.lng,
          })
        },
        {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 0,
        }
      )
    } else {
      setLocationError('Geolocation is not supported by your browser')
      setLocationLoading(false)
      // Use default location
      setCurrentLocation({
        lat: dashboardData.location.lat,
        lon: dashboardData.location.lng,
      })
    }
  }, [])

  const fetchDashboardData = async () => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const headers = getAuthHeader()
      
      const response = await fetch(`${API_BASE_URL}/dashboard`, {
        headers: {
          'Content-Type': 'application/json',
          ...headers,
        },
      })

      if (response.ok) {
        const data = await response.json()
        setDashboardData(data)
      } else {
        // Use sample data if API fails
        console.log('Using sample data')
      }
    } catch (error) {
      console.error('Dashboard fetch error:', error)
      // Continue with sample data
    } finally {
      setLoading(false)
    }
  }

  // Animate numbers
  const [animatedEcoRoutes, setAnimatedEcoRoutes] = useState(0)
  const [animatedCo2, setAnimatedCo2] = useState(0)
  const [animatedScore, setAnimatedScore] = useState(0)

  useEffect(() => {
    const duration = 2000
    const steps = 60
    const stepTime = duration / steps

    const animateValue = (start, end, setter) => {
      let current = start
      const increment = (end - start) / steps
      const timer = setInterval(() => {
        current += increment
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
          current = end
          clearInterval(timer)
        }
        setter(current)
      }, stepTime)
    }

    animateValue(0, dashboardData.sustainability.ecoRoutes, setAnimatedEcoRoutes)
    animateValue(0, dashboardData.sustainability.co2Saved, setAnimatedCo2)
    animateValue(0, dashboardData.sustainability.sustainabilityScore, setAnimatedScore)
  }, [dashboardData.sustainability])

  const sustainabilityData = [
    { name: 'Score', value: dashboardData.sustainability.sustainabilityScore },
    { name: 'Remaining', value: 100 - dashboardData.sustainability.sustainabilityScore },
  ]

  const COLORS = ['#4caf50', '#e0e0e0']

  const weeklyData = [
    { day: 'Mon', routes: 120, speed: 50 },
    { day: 'Tue', routes: 145, speed: 47 },
    { day: 'Wed', routes: 160, speed: 42 },
    { day: 'Thu', routes: 150, speed: 43 },
    { day: 'Fri', routes: 180, speed: 40 },
    { day: 'Sat', routes: 95, speed: 52 },
    { day: 'Sun', routes: 80, speed: 55 },
  ]

  return (
    <ProtectedRoute>
      <div className="dashboard-page">
        <div className="container">
          <motion.div
            className="dashboard-header"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="page-title">
              <span className="title-part">Your</span>{' '}
              <span className="title-part gradient">Dashboard</span>
            </h1>
            <p className="page-subtitle">Personal insights and real-time analytics</p>
            <div className="live-indicator">
              <Zap size={14} />
              <span>Live updates every 5 seconds</span>
            </div>
          </motion.div>

          {/* Sustainability Impact Section */}
          <motion.div
            className="sustainability-card"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
          >
            <div className="sustainability-header">
              <div className="sustainability-title-wrapper">
                <Leaf size={24} className="sustainability-icon" />
                <div>
                  <h2>Your Sustainability Impact</h2>
                  <p>Making a difference, one route at a time.</p>
                </div>
              </div>
              <div className="eco-badge">
                <Users size={14} />
                <span>Eco Warrior</span>
              </div>
            </div>
            <div className="sustainability-metrics">
              <div className="sustainability-metric">
                <div className="metric-value" style={{ color: '#4caf50' }}>
                  {Math.round(animatedEcoRoutes)}
                </div>
                <div className="metric-label">Eco Routes Taken</div>
                <div className="metric-subtext">Out of {dashboardData.sustainability.ecoRoutes} total routes</div>
              </div>
              <div className="sustainability-metric">
                <div className="metric-value" style={{ color: '#2196f3' }}>
                  {animatedCo2.toFixed(1)} kg
                </div>
                <div className="metric-label">CO₂ Saved</div>
                <div className="metric-subtext">Equivalent to planting 3 trees</div>
              </div>
              <div className="sustainability-metric">
                <div className="metric-value" style={{ color: '#ff9800' }}>
                  {Math.round(animatedScore)}%
                </div>
                <div className="metric-label">Sustainability Score</div>
                <div className="sustainability-progress">
                  <div 
                    className="sustainability-progress-bar"
                    style={{ width: `${animatedScore}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Live Location and Recent Routes */}
          <div className="dashboard-grid">
            <motion.div
              className="dashboard-card"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
            >
              <h3 className="card-title">
                <span>A</span> Live Location
              </h3>
              <p className="card-subtitle">Your current position</p>
              <div className="location-content">
                {locationLoading ? (
                  <div className="location-map-placeholder">
                    <MapPin size={48} className="location-pin" />
                    <p className="location-text">Getting your location...</p>
                    <p className="location-coords">Please allow location access</p>
                  </div>
                ) : locationError ? (
                  <div className="location-map-placeholder">
                    <MapPin size={48} className="location-pin" />
                    <p className="location-text">Location unavailable</p>
                    <p className="location-coords" style={{ color: '#ef4444', fontSize: '0.85rem' }}>
                      {locationError}
                    </p>
                    <p className="location-coords">
                      Using default: Lat: {currentLocation?.lat?.toFixed(4) || dashboardData.location.lat}, 
                      Lng: {currentLocation?.lon?.toFixed(4) || dashboardData.location.lng}
                    </p>
                  </div>
                ) : currentLocation ? (
                  <div className="location-map-container">
                    <MapComponent
                      center={[currentLocation.lat, currentLocation.lon]}
                      zoom={15}
                      markers={[
                        {
                          position: [currentLocation.lat, currentLocation.lon],
                          popup: (
                            <div>
                              <strong>Your Location</strong>
                              <br />
                              Lat: {currentLocation.lat.toFixed(6)}
                              <br />
                              Lng: {currentLocation.lon.toFixed(6)}
                            </div>
                          ),
                        },
                      ]}
                      className="dashboard-map"
                    />
                  </div>
                ) : (
                  <div className="location-map-placeholder">
                    <MapPin size={48} className="location-pin" />
                    <p className="location-text">You are here</p>
                    <p className="location-coords">
                      Lat: {dashboardData.location.lat}, Lng: {dashboardData.location.lng}
                    </p>
                  </div>
                )}
                <div className="location-status">
                  <Zap size={14} />
                  <span>
                    {locationLoading
                      ? 'Getting location...'
                      : locationError
                      ? 'Using default location'
                      : 'Location tracking active'}
                  </span>
                </div>
              </div>
            </motion.div>

            <motion.div
              className="dashboard-card"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6, delay: 0.3 }}
            >
              <h3 className="card-title">Recent Routes</h3>
              <p className="card-subtitle">Your travel history</p>
              <div className="recent-routes-content">
                {dashboardData.recentRoutes.length === 0 ? (
                  <p className="empty-state">
                    No routes yet. Start planning to see your history!
                  </p>
                ) : (
                  <ul className="routes-list">
                    {dashboardData.recentRoutes.map((route, index) => (
                      <motion.li
                        key={index}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.4 + index * 0.1 }}
                      >
                        {route.origin} → {route.destination}
                      </motion.li>
                    ))}
                  </ul>
                )}
              </div>
            </motion.div>
          </div>

          {/* Live Stats */}
          <div className="stats-grid">
            {[
              {
                title: 'Active Routes',
                value: dashboardData.stats.activeRoutes.toLocaleString(),
                change: `+${dashboardData.stats.activeRoutesChange}%`,
                icon: TrendingUp,
                color: '#4caf50',
                live: true,
              },
              {
                title: 'Current Congestion',
                value: `${dashboardData.stats.currentCongestion}%`,
                change: 'Normal',
                icon: AlertTriangle,
                color: '#ff9800',
                live: true,
              },
              {
                title: 'Peak Hour',
                value: dashboardData.stats.peakHour,
                change: `${dashboardData.stats.peakCongestion}% congestion`,
                icon: Clock,
                color: '#2196f3',
              },
              {
                title: 'Model Accuracy',
                value: `${dashboardData.stats.modelaccuracy}% +`,
                icon: Users,
                color: '#9c27b0',
              },
            ].map((stat, index) => (
              <motion.div
                key={stat.title}
                className="stat-card"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 0.4 + index * 0.1 }}
                whileHover={{ scale: 1.02, boxShadow: '0 8px 24px rgba(0,0,0,0.12)' }}
              >
                <div className="stat-header">
                  <h4>{stat.title}</h4>
                  {stat.live && (
                    <div className="live-badge">
                      <Zap size={12} />
                      <span>Live</span>
                    </div>
                  )}
                </div>
                <div className="stat-value" style={{ color: stat.color }}>
                  {stat.value}
                </div>
                <div className="stat-change">{stat.change}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </ProtectedRoute>
  )
}

export default Dashboard
