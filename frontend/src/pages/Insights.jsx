import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import ProtectedRoute from '../components/ProtectedRoute'
import { 
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
  PieChart,
  Pie,
  Cell,
  ComposedChart,
  Area,
  AreaChart
} from 'recharts'
import './Insights.css'

const Insights = () => {
  const { getAuthHeader } = useAuth()
  const [trafficData, setTrafficData] = useState(null)
  const [preferencesData, setPreferencesData] = useState(null)
  const [weeklyData, setWeeklyData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchInsightsData()
  }, [])

  const fetchInsightsData = async () => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const headers = getAuthHeader()

      // Fetch all insights data
      const [trafficRes, preferencesRes, weeklyRes] = await Promise.allSettled([
        fetch(`${API_BASE_URL}/insights/traffic`, { headers }),
        fetch(`${API_BASE_URL}/insights/preferences`, { headers }),
        fetch(`${API_BASE_URL}/insights/weekly`, { headers }),
      ])

      if (trafficRes.status === 'fulfilled' && trafficRes.value.ok) {
        setTrafficData(await trafficRes.value.json())
      } else {
        // Sample data
        setTrafficData({
          hours: [
            { time: '6 AM', actual: 45, predicted: 48 },
            { time: '9 AM', actual: 82, predicted: 85 },
            { time: '12 PM', actual: 65, predicted: 68 },
            { time: '3 PM', actual: 52, predicted: 55 },
            { time: '6 PM', actual: 95, predicted: 92 },
            { time: '9 PM', actual: 40, predicted: 42 },
          ],
        })
      }

      if (preferencesRes.status === 'fulfilled' && preferencesRes.value.ok) {
        setPreferencesData(await preferencesRes.value.json())
      } else {
        setPreferencesData({
          fastest: 45,
          ecoFriendly: 35,
          cheapest: 20,
        })
      }

      if (weeklyRes.status === 'fulfilled' && weeklyRes.value.ok) {
        setWeeklyData(await weeklyRes.value.json())
      } else {
        setWeeklyData({
          days: [
            { day: 'Mon', routes: 120, speed: 50 },
            { day: 'Tue', routes: 145, speed: 47 },
            { day: 'Wed', routes: 160, speed: 42 },
            { day: 'Thu', routes: 150, speed: 43 },
            { day: 'Fri', routes: 180, speed: 40 },
            { day: 'Sat', routes: 95, speed: 52 },
            { day: 'Sun', routes: 80, speed: 55 },
          ],
        })
      }
    } catch (error) {
      console.error('Insights fetch error:', error)
    } finally {
      setLoading(false)
    }
  }

  const preferencesChartData = preferencesData
    ? [
        { name: 'Fastest', value: preferencesData.fastest, color: '#2196f3' },
        { name: 'Eco-Friendly', value: preferencesData.ecoFriendly, color: '#4caf50' },
        { name: 'Cheapest', value: preferencesData.cheapest, color: '#ff9800' },
      ]
    : []

  const COLORS = ['#2196f3', '#4caf50', '#ff9800']

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="custom-tooltip">
          <p className="tooltip-label">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }}>
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <ProtectedRoute>
      <div className="insights-page">
        <div className="container">
          <motion.div
            className="insights-header"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="page-title">
              <span className="title-part gradient">Insights</span>
            </h1>
          </motion.div>

          {/* Peak Traffic Hours */}
          {trafficData && (
            <motion.div
              className="insight-card"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
            >
              <div className="card-header-insight">
                <div>
                  <h2>Peak Traffic Hours</h2>
                  <p>Actual vs AI-predicted congestion levels</p>
                </div>
                <div className="ai-badge">
                  <span>AI Powered</span>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={300}>
                <ComposedChart data={trafficData.hours}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
                  <XAxis 
                    dataKey="time" 
                    stroke="#4a5568"
                    style={{ fontFamily: 'Inter, sans-serif', fontSize: '0.85rem' }}
                  />
                  <YAxis 
                    stroke="#4a5568"
                    style={{ fontFamily: 'Inter, sans-serif', fontSize: '0.85rem' }}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="actual"
                    fill="#2196f3"
                    fillOpacity={0.3}
                    stroke="#2196f3"
                    strokeWidth={2}
                  />
                  <Line
                    type="monotone"
                    dataKey="predicted"
                    stroke="#4caf50"
                    strokeWidth={2}
                    dot={{ fill: '#4caf50', r: 4 }}
                  />
                </ComposedChart>
              </ResponsiveContainer>
            </motion.div>
          )}

          {/* Route Preferences and Weekly Activity */}
          <div className="insights-grid">
            {preferencesData && (
              <motion.div
                className="insight-card"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.6, delay: 0.2 }}
              >
                <h2>Route Preferences</h2>
                <p className="card-subtitle">Distribution of route type selections</p>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={preferencesChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                      animationBegin={0}
                      animationDuration={1000}
                    >
                      {preferencesChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                <div className="preferences-legend">
                  <div className="legend-item">
                    <div className="legend-dot" style={{ backgroundColor: '#2196f3' }}></div>
                    <span>Fastest ({preferencesData.fastest}%)</span>
                  </div>
                  <div className="legend-item">
                    <div className="legend-dot" style={{ backgroundColor: '#4caf50' }}></div>
                    <span>Eco-Friendly ({preferencesData.ecoFriendly}%)</span>
                  </div>
                  <div className="legend-item">
                    <div className="legend-dot" style={{ backgroundColor: '#ff9800' }}></div>
                    <span>Cheapest ({preferencesData.cheapest}%)</span>
                  </div>
                </div>
              </motion.div>
            )}

            {weeklyData && (
              <motion.div
                className="insight-card"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.6, delay: 0.3 }}
              >
                <h2>Weekly Route Activity & Speed Analysis</h2>
                <p className="card-subtitle">Routes planned and average speed per day</p>
                <ResponsiveContainer width="100%" height={300}>
                  <ComposedChart data={weeklyData.days}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
                    <XAxis 
                      dataKey="day" 
                      stroke="#4a5568"
                      style={{ fontFamily: 'Inter, sans-serif', fontSize: '0.85rem' }}
                    />
                    <YAxis 
                      yAxisId="left"
                      stroke="#4a5568"
                      label={{ value: 'Routes Planned', angle: -90, position: 'insideLeft' }}
                      style={{ fontFamily: 'Inter, sans-serif', fontSize: '0.85rem' }}
                    />
                    <YAxis 
                      yAxisId="right"
                      orientation="right"
                      stroke="#4a5568"
                      label={{ value: 'Avg Speed (km/h)', angle: 90, position: 'insideRight' }}
                      style={{ fontFamily: 'Inter, sans-serif', fontSize: '0.85rem' }}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Legend />
                    <Bar 
                      yAxisId="left"
                      dataKey="routes" 
                      fill="#4caf50"
                      radius={[4, 4, 0, 0]}
                    />
                    <Line
                      yAxisId="right"
                      type="monotone"
                      dataKey="speed"
                      stroke="#ff9800"
                      strokeWidth={2}
                      dot={{ fill: '#ff9800', r: 4 }}
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </motion.div>
            )}
          </div>
        </div>
      </div>
    </ProtectedRoute>
  )
}

export default Insights

