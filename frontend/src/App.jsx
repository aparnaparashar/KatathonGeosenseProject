import React, { useState } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { GeoProvider } from './context/GeoContext'
import Navbar from './components/Navbar'
import LogoIntro from './components/LogoIntro'
import ProtectedRoute from './components/ProtectedRoute'
import Home from './pages/Home'
import SignIn from './pages/SignIn'
import SignUp from './pages/SignUp'
import SmartRoutes from './pages/SmartRoutes'
import Dashboard from './pages/Dashboard'
import Insights from './pages/Insights'
import Pooling from './pages/Pooling'
import Profile from './pages/Profile'
import './App.css'

function AppContent() {
  const [introComplete, setIntroComplete] = useState(false)
  const { isAuthenticated } = useAuth()

  if (!introComplete) {
    return <LogoIntro onComplete={() => setIntroComplete(true)} />
  }

  return (
    <div className="App">
      <Navbar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route 
            path="/signin" 
            element={
              isAuthenticated ? <Navigate to="/dashboard" replace /> : <SignIn />
            } 
          />
          <Route 
            path="/signup" 
            element={
              isAuthenticated ? <Navigate to="/dashboard" replace /> : <SignUp />
            } 
          />
          <Route 
            path="/smart-routes" 
            element={
              <ProtectedRoute>
                <SmartRoutes />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/dashboard" 
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/insights" 
            element={
              <ProtectedRoute>
                <Insights />
              </ProtectedRoute>
            } 
          />
          <Route path="/pooling" element={<Pooling />} />
          <Route 
            path="/profile" 
            element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            } 
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  return (
    <AuthProvider>
      <GeoProvider>
        <Router>
          <AppContent />
        </Router>
      </GeoProvider>
    </AuthProvider>
  )
}

export default App
