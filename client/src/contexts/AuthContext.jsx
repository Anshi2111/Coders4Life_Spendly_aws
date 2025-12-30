import React, { createContext, useContext, useState, useEffect } from 'react'
import api from '../services/api'

const AuthContext = createContext()

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Check if user is logged in on app start
  useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) {
      // Verify token and get user data
      api.get('/user/profile')
        .then(response => {
          setUser(response.data.user)
        })
        .catch(error => {
          console.error('Token verification failed:', error)
          localStorage.removeItem('token')
        })
        .finally(() => {
          setLoading(false)
        })
    } else {
      setLoading(false)
    }
  }, [])

  const login = async (email, password) => {
    try {
      setError(null)
      setLoading(true)
      
      const response = await api.post('/auth/login', { email, password })
      const { token, user: userData } = response.data
      
      localStorage.setItem('token', token)
      setUser(userData)
      
      return { success: true }
    } catch (error) {
      const message = error.response?.data?.message || 'Login failed'
      setError(message)
      return { success: false, error: message }
    } finally {
      setLoading(false)
    }
  }

  const register = async (email, password, name, phone) => {
    try {
      setError(null)
      setLoading(true)
      
      const response = await api.post('/auth/register', { email, password, name, phone })
      const { token, user: userData } = response.data
      
      localStorage.setItem('token', token)
      setUser(userData)
      
      return { success: true }
    } catch (error) {
      const message = error.response?.data?.message || 'Registration failed'
      setError(message)
      return { success: false, error: message }
    } finally {
      setLoading(false)
    }
  }

  const logout = () => {
    localStorage.removeItem('token')
    setUser(null)
    setError(null)
  }

  const updateUser = (userData) => {
    setUser(prev => ({ ...prev, ...userData }))
  }

  const clearError = () => {
    setError(null)
  }

  const value = {
    user,
    loading,
    error,
    login,
    register,
    logout,
    updateUser,
    clearError
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}