import React, { createContext, useContext, useState } from 'react'

const GeoContext = createContext()

export const useGeo = () => {
  const context = useContext(GeoContext)
  if (!context) {
    throw new Error('useGeo must be used within a GeoProvider')
  }
  return context
}

export const GeoProvider = ({ children }) => {
  const [selectedLocation, setSelectedLocation] = useState(null)
  const [trafficData, setTrafficData] = useState([])
  const [routes, setRoutes] = useState([])

  const value = {
    selectedLocation,
    setSelectedLocation,
    trafficData,
    setTrafficData,
    routes,
    setRoutes
  }

  return <GeoContext.Provider value={value}>{children}</GeoContext.Provider>
}

