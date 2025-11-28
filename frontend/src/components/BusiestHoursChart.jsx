import React from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { motion } from 'framer-motion'
import './BusiestHoursChart.css'

const BusiestHoursChart = ({ data = [] }) => {
  // Default sample data if none provided
  const chartData = data.length > 0 
    ? data 
    : Array.from({ length: 24 }, (_, i) => ({
        hour: `${i}:00`,
        traffic: Math.floor(Math.random() * 100)
      }))

  return (
    <motion.div
      className="busiest-hours-chart"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <h3>Busiest Hours Analysis</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="hour" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Bar dataKey="traffic" fill="#667eea" />
        </BarChart>
      </ResponsiveContainer>
    </motion.div>
  )
}

export default BusiestHoursChart

