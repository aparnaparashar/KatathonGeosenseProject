import React, { useState } from 'react'
import { motion } from 'framer-motion'
import './ReportsPage.css'

const ReportsPage = () => {
  const [reportType, setReportType] = useState('traffic')
  const [stakeholderType, setStakeholderType] = useState('government')
  const [format, setFormat] = useState('pdf')

  const handleGenerateReport = async () => {
    // TODO: Implement report generation API call
    console.log('Generating report...', { reportType, stakeholderType, format })
  }

  return (
    <motion.div
      className="reports-page"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <h1>Report Generation</h1>
      <p className="subtitle">Generate reports for government, researchers, and civil engineers</p>
      
      <div className="report-form">
        <div className="form-group">
          <label>Report Type</label>
          <select
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
          >
            <option value="traffic">Traffic Analysis</option>
            <option value="mobility">Mobility Patterns</option>
            <option value="poi">POI Analysis</option>
            <option value="routes">Route Analysis</option>
          </select>
        </div>
        
        <div className="form-group">
          <label>Stakeholder Type</label>
          <select
            value={stakeholderType}
            onChange={(e) => setStakeholderType(e.target.value)}
          >
            <option value="government">Government</option>
            <option value="researcher">Researcher</option>
            <option value="engineer">Civil Engineer</option>
          </select>
        </div>
        
        <div className="form-group">
          <label>Format</label>
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value)}
          >
            <option value="pdf">PDF</option>
            <option value="csv">CSV</option>
          </select>
        </div>
        
        <button onClick={handleGenerateReport} className="generate-button">
          Generate Report
        </button>
      </div>
      
      <div className="reports-list">
        <h2>Recent Reports</h2>
        <p>No reports generated yet.</p>
      </div>
    </motion.div>
  )
}

export default ReportsPage

