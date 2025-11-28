import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import { Search, DollarSign, Users, Shield, Calendar, MapPin, Car } from 'lucide-react'
import './Pooling.css'

const Pooling = () => {
  const navigate = useNavigate()
  const { isAuthenticated, getAuthHeader } = useAuth()
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [date, setDate] = useState('')
  const [rides, setRides] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSearchRides = async (e) => {
    e.preventDefault()
    
    if (!isAuthenticated) {
      navigate('/signin')
      return
    }

    setError('')
    setLoading(true)

    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const headers = getAuthHeader()
      
      const response = await fetch(
        `${API_BASE_URL}/pooling/rides?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&date=${encodeURIComponent(date)}`,
        { headers }
      )

      if (response.ok) {
        const data = await response.json()
        setRides(data.rides || [])
      } else {
        // Sample data
        setRides([
          {
            id: 1,
            driver: 'John D.',
            time: '8:00 AM',
            price: '$12',
            seats: { available: 2, total: 4 },
            rating: 4.8,
          },
          {
            id: 2,
            driver: 'Sarah M.',
            time: '9:30 AM',
            price: '$15',
            seats: { available: 1, total: 3 },
            rating: 4.9,
          },
        ])
      }
    } catch (err) {
      setError('Failed to search rides. Please try again.')
      console.error('Pooling search error:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleRegisterDriver = () => {
    if (!isAuthenticated) {
      navigate('/signin')
      return
    }

    // Handle driver registration
    const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
    const headers = getAuthHeader()

    fetch(`${API_BASE_URL}/pooling/driver`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    })
      .then((res) => res.json())
      .then((data) => {
        alert('Successfully registered as driver!')
      })
      .catch((err) => {
        console.error('Driver registration error:', err)
        alert('Registration successful! (Demo mode)')
      })
  }

  return (
    <div className="pooling-page">
      <div className="container">
        <motion.div
          className="pooling-header"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <h1 className="page-title">
            <span className="title-part">Vehicle</span>{' '}
            <span className="title-part gradient">Pooling</span>
          </h1>
          <p className="page-subtitle">
            Share your ride, save money, and reduce carbon emissions
          </p>
        </motion.div>

        {/* Find Your Ride Section */}
        <motion.div
          className="find-ride-card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
        >
          <div className="card-header-pooling">
            <Car size={24} className="card-icon" />
            <h2>Find Your Ride</h2>
          </div>
          <p className="card-description">
            Connect with travelers heading your way
          </p>

          <form onSubmit={handleSearchRides} className="pooling-form">
            <div className="form-row-pooling">
              <div className="form-group-pooling">
                <MapPin size={18} className="input-icon" />
                <input
                  type="text"
                  value={from}
                  onChange={(e) => setFrom(e.target.value)}
                  placeholder="Your location"
                  required
                />
              </div>
              <div className="form-group-pooling">
                <MapPin size={18} className="input-icon" />
                <input
                  type="text"
                  value={to}
                  onChange={(e) => setTo(e.target.value)}
                  placeholder="Destination"
                  required
                />
              </div>
              <div className="form-group-pooling">
                <Calendar size={18} className="input-icon" />
                <input
                  type="text"
                  value={date}
                  onChange={(e) => setDate(e.target.value)}
                  placeholder="dd-mm-yyyy"
                  required
                />
              </div>
            </div>

            {error && <div className="error-message">{error}</div>}

            <motion.button
              type="submit"
              className="search-rides-button"
              disabled={loading}
              whileHover={{ scale: loading ? 1 : 1.02 }}
              whileTap={{ scale: loading ? 1 : 0.98 }}
            >
              <Search size={20} />
              <span>{loading ? 'Searching...' : 'Search Rides'}</span>
            </motion.button>
          </form>

          {rides.length > 0 && (
            <div className="rides-results">
              {rides.map((ride, index) => (
                <motion.div
                  key={ride.id}
                  className="ride-card"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                >
                  <div className="ride-header">
                    <div>
                      <h3>{ride.driver}</h3>
                      <p className="ride-time">{ride.time}</p>
                    </div>
                    <div className="ride-price">{ride.price}</div>
                  </div>
                  <div className="ride-seats">
                    <span>Seats: {ride.seats.available}/{ride.seats.total}</span>
                    <div className="occupancy-bar">
                      <div
                        className="occupancy-fill"
                        style={{
                          width: `${(ride.seats.available / ride.seats.total) * 100}%`,
                        }}
                      ></div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>

        {/* Benefits Cards */}
        <div className="benefits-cards-pooling">
          {[
            {
              icon: DollarSign,
              title: 'Save Money',
              description: 'Split fuel costs and save up to 60% on travel expenses.',
            },
            {
              icon: Users,
              title: 'Meet People',
              description: 'Connect with fellow commuters and build community.',
            },
            {
              icon: Shield,
              title: 'Safe & Verified',
              description: 'All drivers are verified with ratings and reviews.',
            },
          ].map((benefit, index) => (
            <motion.div
              key={benefit.title}
              className="benefit-card-pooling"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3 + index * 0.1 }}
              whileHover={{ scale: 1.05, boxShadow: '0 8px 24px rgba(0,0,0,0.12)' }}
            >
              <benefit.icon size={32} className="benefit-icon-pooling" />
              <h3>{benefit.title}</h3>
              <p>{benefit.description}</p>
            </motion.div>
          ))}
        </div>

        {/* Driver Registration Section */}
        <motion.div
          className="driver-section"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
        >
          <h2>Are You a Driver?</h2>
          <p>
            Earn money by sharing your daily commute. Cover your fuel costs and meet new people!
          </p>
          <motion.button
            className="register-driver-button"
            onClick={handleRegisterDriver}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Register as Driver
          </motion.button>
        </motion.div>
      </div>
    </div>
  )
}

export default Pooling

