import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import './SignIn.css'

const SignUp = () => {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { signup, isAuthenticated } = useAuth()

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard')
    }
  }, [isAuthenticated, navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    // Validation
    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long')
      return
    }

    if (!name.trim()) {
      setError('Name is required')
      return
    }

    setLoading(true)

    const result = await signup(email, password, name)

    if (result.success) {
      navigate('/dashboard')
    } else {
      setError(result.error || 'Signup failed. Please try again.')
    }

    setLoading(false)
  }

  return (
    <div className="signin-page">
      <div className="signin-background"></div>
      <motion.div
        className="signin-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="signin-header">
          <div className="signin-logo-icon">
            <svg viewBox="0 0 100 100" className="signin-logo-svg">
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
          <h1 className="signin-brand">
            <span className="signin-geo">Geo</span>
            <span className="signin-sense">Sense</span>
          </h1>
          <p className="signin-tagline">Create your GeoSense account</p>
        </div>

        <div className="signin-tabs">
          <button className="signin-tab" onClick={() => navigate('/signin')}>
            Sign In
          </button>
          <button className="signin-tab active">Sign Up</button>
        </div>

        <form onSubmit={handleSubmit} className="signin-form">
          <div className="form-group">
            <label htmlFor="name">Name</label>
            <input
              type="text"
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your full name"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Create a password (min. 6 characters)"
              required
              minLength={6}
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password</label>
            <input
              type="password"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm your password"
              required
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <motion.button
            type="submit"
            className="signin-button"
            disabled={loading}
            whileHover={{ scale: loading ? 1 : 1.02 }}
            whileTap={{ scale: loading ? 1 : 0.98 }}
          >
            {loading ? 'Creating Account...' : 'Sign Up'}
          </motion.button>
        </form>
      </motion.div>
    </div>
  )
}

export default SignUp
