import React from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import { ArrowRight, Car, Shield, Zap, Route, Leaf, DollarSign, TrendingUp, Clock } from 'lucide-react'
import heroCity from '../../hero-city.jpg'
import './Home.css'
import Chatbot from '../components/Chatbot'

const Home = () => {
  const navigate = useNavigate()
  const { isAuthenticated } = useAuth()

  const handleGetStarted = () => {
    if (isAuthenticated) {
      navigate('/dashboard')
    } else {
      navigate('/signin')
    }
  }

  const handleViewInsights = () => {
    if (isAuthenticated) {
      navigate('/insights')
    } else {
      navigate('/signin')
    }
  }

  return (
    <div className="home-page">
      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-container">
          <motion.div
            className="hero-content"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="hero-title">
              <span className="gradient-text">GeoSense</span>
              <br />
              <span className="hero-subtitle">Smart Urban Insights</span>
            </h1>
            <p className="hero-description">
              Navigate cities smarter with AI-powered routing, real-time traffic analytics, and predictive insights. 
              Choose from fastest, eco-friendly, or cost-efficient routes.
            </p>
            <div className="hero-buttons">
              <motion.button
                className="btn-primary"
                onClick={handleGetStarted}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                Get Started <ArrowRight size={20} />
              </motion.button>
              <motion.button
                className="btn-secondary"
                onClick={handleViewInsights}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                View Insights
              </motion.button>
            </div>
          </motion.div>
          <motion.div
            className="hero-visual"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <img src={heroCity} alt="City skyline" className="hero-city-img" />
          </motion.div>
        </div>
      </section>

      {/* Experience the Future Section */}
      <section className="experience-section">
        <div className="container">
          <motion.h2
            className="section-title"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
          >
            Experience the Future
          </motion.h2>
          <p className="section-subtitle">
            Join thousands using GeoSense for intelligent urban mobility.
          </p>
          <div className="feature-cards">
            {[
              {
                icon: Car,
                title: 'Vehicle Pooling',
                description: 'Connect with travelers going your way.',
              },
              {
                icon: Shield,
                title: 'Smart & Secure',
                description: 'Your data protected with enterprise-grade security.',
              },
              {
                icon: Zap,
                title: 'AI-Powered',
                description: 'Machine learning optimizes every route.',
              },
            ].map((feature, index) => (
              <motion.div
                key={feature.title}
                className="feature-card"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                whileHover={{ scale: 1.05, boxShadow: '0 8px 24px rgba(0,0,0,0.12)' }}
              >
                <feature.icon size={32} className="feature-icon" />
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Route Benefits Section */}
      <section className="benefits-section">
        <div className="container">
          <div className="benefits-grid">
            {[
              {
                icon: Route,
                title: 'Fastest Route',
                description: 'AI-optimized paths that get you there in record time.',
              },
              {
                icon: Leaf,
                title: 'Eco-Friendly',
                description: 'Reduce carbon footprint with sustainable route options.',
              },
              {
                icon: DollarSign,
                title: 'Cost Efficient',
                description: 'Save money with optimal fuel consumption routes.',
              },
              {
                icon: TrendingUp,
                title: 'Predictive Analytics',
                description: 'ML-powered traffic forecasts and congestion alerts.',
              },
              {
                icon: Clock,
                title: 'Live Traffic',
                description: 'Real-time traffic updates and incident reporting.',
              },
              {
                icon: Zap,
                title: 'Peak Time Insights',
                description: 'Data-driven insights on optimal travel times.',
              },
            ].map((benefit, index) => (
              <motion.div
                key={benefit.title}
                className="benefit-card"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                whileHover={{ scale: 1.02, boxShadow: '0 8px 24px rgba(0,0,0,0.12)' }}
              >
                <benefit.icon size={28} className="benefit-icon" />
                <h3>{benefit.title}</h3>
                <p>{benefit.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Why Choose GeoSense Section */}
      <section className="why-choose-section">
        <div className="container">
          <motion.h2
            className="section-title"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
          >
            Why Choose GeoSense?
          </motion.h2>
          <p className="section-subtitle">
            Advanced machine learning meets urban mobility for smarter city navigation.
          </p>
          <div className="highlight-cards">
            {[
              { icon: Route, title: 'Fastest Route', color: '#2196f3' },
              { icon: Leaf, title: 'Eco-Friendly', color: '#4caf50' },
              { icon: DollarSign, title: 'Cost Efficient', color: '#ff9800' },
            ].map((highlight, index) => (
              <motion.div
                key={highlight.title}
                className="highlight-card"
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                whileHover={{ scale: 1.05 }}
              >
                <div className="highlight-icon-wrapper" style={{ backgroundColor: `${highlight.color}20` }}>
                  <highlight.icon size={32} style={{ color: highlight.color }} />
                </div>
                <h3>{highlight.title}</h3>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Footer */}
      <section className="cta-section">
        <div className="container">
          <motion.h2
            className="cta-title"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
          >
            Ready to Transform Your Commute?
          </motion.h2>
          <p className="cta-subtitle">
            Join thousands using GeoSense for smarter, faster, and greener urban navigation. 
            Experience AI-powered routing today.
          </p>
          <motion.button
            className="btn-primary btn-large"
            onClick={handleGetStarted}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Create Free Account
          </motion.button>
          <div className="footer-text">
            <p>GeoSense – Powered by AI for Urban Mobility</p>
            <p>2025 GeoSense. All rights reserved.</p>
          </div>
          <div className="built-by">
            <p>Built by Team Polaris — members: Aparna Parashar, Navya Mishra, Sneha Patil, Puja Kukade, Muskan Surlia</p>
          </div>
        </div>
      </section>
      <Chatbot />
    </div>
  )
}

export default Home

