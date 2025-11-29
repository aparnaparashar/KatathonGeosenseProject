import React, { createContext, useContext, useState, useEffect } from 'react'

const AuthContext = createContext()

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(null)
  const [loading, setLoading] = useState(true)

  // Check for existing token on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('geosense_token')
    const storedUser = localStorage.getItem('geosense_user')
    
    if (storedToken && storedUser) {
      try {
        setToken(storedToken)
        setUser(JSON.parse(storedUser))
      } catch (error) {
        console.error('Error parsing stored user data:', error)
        localStorage.removeItem('geosense_token')
        localStorage.removeItem('geosense_user')
      }
    }
    setLoading(false)
  }, [])

  const login = async (email, password) => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {  // FIXED: added /api/
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || 'Login failed')
      }

      const data = await response.json()
      const { token: newToken, user: userData } = data

      // Store token and user
      localStorage.setItem('geosense_token', newToken)
      localStorage.setItem('geosense_user', JSON.stringify(userData))
      
      setToken(newToken)
      setUser(userData)
      
      return { success: true }
    } catch (error) {
      console.error('Login error:', error)
      return { success: false, error: error.message }
    }
  }

  const signup = async (email, password, name) => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {  // FIXED: added /api/
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, name }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || 'Signup failed')
      }

      const data = await response.json()
      const { token: newToken, user: userData } = data

      // Store token and user
      localStorage.setItem('geosense_token', newToken)
      localStorage.setItem('geosense_user', JSON.stringify(userData))
      
      setToken(newToken)
      setUser(userData)
      
      return { success: true }
    } catch (error) {
      console.error('Signup error:', error)
      return { success: false, error: error.message }
    }
  }

  const logout = () => {
    localStorage.removeItem('geosense_token')
    localStorage.removeItem('geosense_user')
    setToken(null)
    setUser(null)
  }

  const getAuthHeader = () => {
    if (!token) return {}
    return { Authorization: `Bearer ${token}` }
  }

  const isAuthenticated = !!token

  const value = {
    user,
    token,
    isAuthenticated,
    loading,
    login,
    signup,
    logout,
    getAuthHeader,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}