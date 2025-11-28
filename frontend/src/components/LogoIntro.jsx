import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import './LogoIntro.css'

const LogoIntro = ({ onComplete }) => {
  const [showIntro, setShowIntro] = useState(false)

  useEffect(() => {
    // Check if intro has been shown in this session
    const introShown = sessionStorage.getItem('geosense_intro_shown')
    
    if (!introShown) {
      setShowIntro(true)
      sessionStorage.setItem('geosense_intro_shown', 'true')
      
      // Auto-complete after animation
      setTimeout(() => {
        setShowIntro(false)
        setTimeout(() => onComplete(), 500)
      }, 2000)
    } else {
      onComplete()
    }
  }, [onComplete])

  return (
    <AnimatePresence>
      {showIntro && (
        <motion.div
          className="logo-intro"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.5 }}
        >
          <motion.div
            className="logo-intro-content"
            initial={{ scale: 1.5, opacity: 0.3, filter: 'blur(10px)' }}
            animate={{ scale: 1, opacity: 1, filter: 'blur(0px)' }}
            transition={{ duration: 1.5, ease: 'easeOut' }}
          >
            <motion.div
              className="logo-icon"
              initial={{ rotate: -180 }}
              animate={{ rotate: 0 }}
              transition={{ duration: 1, ease: 'easeOut' }}
            >
              <svg viewBox="0 0 100 100" className="logo-svg">
                {/* Map pin background circle */}
                <circle cx="50" cy="50" r="45" fill="#1a237e" />
                {/* Curved route inside */}
                <path
                  d="M 20 50 Q 50 20, 80 50 Q 50 80, 20 50"
                  stroke="#4caf50"
                  strokeWidth="4"
                  fill="none"
                  strokeLinecap="round"
                />
                {/* Pin outline */}
                <path
                  d="M 50 20 L 60 50 L 50 70 L 40 50 Z"
                  fill="none"
                  stroke="#ffffff"
                  strokeWidth="3"
                  strokeLinejoin="round"
                />
              </svg>
            </motion.div>
            <motion.h1
              className="logo-text"
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.5, duration: 0.8 }}
            >
              GeoSense
            </motion.h1>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default LogoIntro

