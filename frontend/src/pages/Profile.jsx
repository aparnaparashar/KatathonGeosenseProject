import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import ProtectedRoute from '../components/ProtectedRoute'
import { Download, Route, TrendingUp, DollarSign } from 'lucide-react'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import './Profile.css'

const Profile = () => {
  const { user, getAuthHeader } = useAuth()
  const [profileData, setProfileData] = useState({
    email: user?.email || 'aparna.tech123@gmail.com',
    memberSince: '10/11/2025',
    accountStatus: 'Active',
    stats: {
      routesSaved: 0,
      totalDistance: 0,
      totalCost: 0,
    },
    distanceHistory: [],
    routesPerWeek: [],
    recentRoutes: [],
  })
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)

  useEffect(() => {
    fetchProfileData()
  }, [])

  const fetchProfileData = async () => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const headers = getAuthHeader()

      const [profileRes, statsRes, routesRes] = await Promise.allSettled([
        fetch(`${API_BASE_URL}/user/profile`, { headers }),
        fetch(`${API_BASE_URL}/user/stats`, { headers }),
        fetch(`${API_BASE_URL}/user/routes`, { headers }),
      ])

      if (profileRes.status === 'fulfilled' && profileRes.value.ok) {
        const data = await profileRes.value.json()
        setProfileData((prev) => ({ ...prev, ...data }))
      }

      if (statsRes.status === 'fulfilled' && statsRes.value.ok) {
        const data = await statsRes.value.json()
        setProfileData((prev) => ({
          ...prev,
          stats: data.stats || prev.stats,
          distanceHistory: data.distanceHistory || [],
          routesPerWeek: data.routesPerWeek || [],
        }))
      }

      if (routesRes.status === 'fulfilled' && routesRes.value.ok) {
        const data = await routesRes.value.json()
        setProfileData((prev) => ({
          ...prev,
          recentRoutes: data.routes || [],
        }))
      }
    } catch (error) {
      console.error('Profile fetch error:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleDownloadCSV = async () => {
    setDownloading(true)
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const headers = getAuthHeader()

      const response = await fetch(`${API_BASE_URL}/user/stats/csv`, { headers })
      
      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = 'geosense-stats.csv'
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
      } else {
        alert('CSV download initiated! (Demo mode)')
      }
    } catch (error) {
      console.error('CSV download error:', error)
      alert('CSV download initiated! (Demo mode)')
    } finally {
      setDownloading(false)
    }
  }

  // Sample data for charts if API doesn't return data
  const distanceHistoryData = profileData.distanceHistory.length > 0
    ? profileData.distanceHistory
    : [
        { date: 'Week 1', distance: 120 },
        { date: 'Week 2', distance: 150 },
        { date: 'Week 3', distance: 180 },
        { date: 'Week 4', distance: 200 },
      ]

  const routesPerWeekData = profileData.routesPerWeek.length > 0
    ? profileData.routesPerWeek
    : [
        { week: 'Week 1', routes: 15 },
        { week: 'Week 2', routes: 20 },
        { week: 'Week 3', routes: 18 },
        { week: 'Week 4', routes: 25 },
      ]

  return (
    <ProtectedRoute>
      <div className="profile-page">
        <div className="container">
          <motion.div
            className="profile-header"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="page-title">
              <span className="title-part">Your</span>{' '}
              <span className="title-part gradient">Profile</span>
            </h1>
            <p className="page-subtitle">
              Manage your GeoSense account and route history
            </p>
          </motion.div>

          {/* Account Information */}
          <motion.div
            className="profile-card"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
          >
            <h2>Account Information</h2>
            <p className="card-subtitle">Your GeoSense account details</p>
            <div className="account-info">
              <div className="info-row">
                <span className="info-label">Email</span>
                <span className="info-value">{profileData.email}</span>
              </div>
              <div className="info-row">
                <span className="info-label">Member Since</span>
                <span className="info-value">{profileData.memberSince}</span>
              </div>
              <div className="info-row">
                <span className="info-label">Account Status</span>
                <span className="info-value status-active">{profileData.accountStatus}</span>
              </div>
            </div>
          </motion.div>

          {/* Usage Statistics */}
          <motion.div
            className="profile-card"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <h2>Usage Statistics</h2>
            <p className="card-subtitle">Your GeoSense activity overview</p>
            
            <div className="stats-grid-profile">
              <div className="stat-item-profile">
                <Route size={24} className="stat-icon" />
                <div className="stat-value-profile">{profileData.stats.routesSaved}</div>
                <div className="stat-label-profile">Routes Saved</div>
              </div>
              <div className="stat-item-profile">
                <TrendingUp size={24} className="stat-icon" />
                <div className="stat-value-profile">{profileData.stats.totalDistance.toFixed(1)} km</div>
                <div className="stat-label-profile">Total Distance</div>
              </div>
              <div className="stat-item-profile">
                <DollarSign size={24} className="stat-icon" />
                <div className="stat-value-profile">${profileData.stats.totalCost.toFixed(2)}</div>
                <div className="stat-label-profile">Total Cost</div>
              </div>
            </div>

            <div className="charts-section">
              <div className="chart-container">
                <h3>Total Distance Over Time</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={distanceHistoryData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
                    <XAxis dataKey="date" stroke="#4a5568" />
                    <YAxis stroke="#4a5568" />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="distance"
                      stroke="#2196f3"
                      fill="#2196f3"
                      fillOpacity={0.3}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-container">
                <h3>Routes Saved Per Week</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={routesPerWeekData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
                    <XAxis dataKey="week" stroke="#4a5568" />
                    <YAxis stroke="#4a5568" />
                    <Tooltip />
                    <Bar dataKey="routes" fill="#4caf50" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <motion.button
              className="csv-button"
              onClick={handleDownloadCSV}
              disabled={downloading}
              whileHover={{ scale: downloading ? 1 : 1.02 }}
              whileTap={{ scale: downloading ? 1 : 0.98 }}
            >
              <Download size={18} />
              <span>{downloading ? 'Downloading...' : 'CSV Report'}</span>
            </motion.button>
          </motion.div>

          {/* Recent Route History */}
          <motion.div
            className="profile-card"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
          >
            <h2>Recent Route History</h2>
            {profileData.recentRoutes.length === 0 ? (
              <p className="empty-state">
                No routes saved yet. Start planning routes to see them here!
              </p>
            ) : (
              <ul className="routes-history-list">
                {profileData.recentRoutes.map((route, index) => (
                  <motion.li
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.4 + index * 0.1 }}
                  >
                    <div className="route-history-item">
                      <span className="route-path">
                        {route.origin} → {route.destination}
                      </span>
                      <span className="route-date">{route.date}</span>
                    </div>
                  </motion.li>
                ))}
              </ul>
            )}
          </motion.div>
        </div>
      </div>
    </ProtectedRoute>
  )
}

export default Profile

