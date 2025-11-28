import React from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import GeoSenseLogo from './GeoSenseLogo'
import { User, LogOut, Home, Route, BarChart3, Users } from 'lucide-react'
import './Navbar.css'

const Navbar = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const { isAuthenticated, logout, user } = useAuth()

  const handleLogout = () => {
    logout()
    navigate('/')
  }

  const publicNavItems = [
    { path: '/', label: 'Home', icon: Home },
    { path: '/smart-routes', label: 'Smart Routes', icon: Route },
    { path: '/insights', label: 'Insights', icon: BarChart3 },
    { path: '/pooling', label: 'Pooling', icon: Users },
  ]

  const authNavItems = [
    { path: '/', label: 'Home', icon: Home },
    { path: '/smart-routes', label: 'Smart Routes', icon: Route },
    { path: '/insights', label: 'Insights', icon: BarChart3 },
    { path: '/pooling', label: 'Pooling', icon: Users },
    { path: '/dashboard', label: 'Dashboard', icon: BarChart3 },
    { path: '/profile', label: 'Profile', icon: User },
  ]

  const navItems = isAuthenticated ? authNavItems : publicNavItems

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <GeoSenseLogo />
        <ul className="navbar-menu">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.path
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`navbar-link ${isActive ? 'active' : ''}`}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                </Link>
              </li>
            )
          })}
        </ul>
        <div className="navbar-auth">
          {isAuthenticated ? (
            <>
              <div className="navbar-user">
                <User size={18} />
                <span>{user?.email?.split('@')[0] || 'User'}</span>
              </div>
              <motion.button
                className="navbar-signout"
                onClick={handleLogout}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <LogOut size={18} />
                <span>Sign Out</span>
              </motion.button>
            </>
          ) : (
            <Link to="/signin" className="navbar-signin">
              Sign In
            </Link>
          )}
        </div>
      </div>
    </nav>
  )
}

export default Navbar
