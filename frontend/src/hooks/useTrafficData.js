import { useState, useEffect } from 'react'
import { getTrafficData } from '../utils/api'

export const useTrafficData = (location) => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!location) return

    const fetchData = async () => {
      setLoading(true)
      setError(null)
      try {
        const result = await getTrafficData(location)
        setData(result)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [location])

  return { data, loading, error }
}

