import axios from 'axios'

// Get API base URL from environment or use default
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

console.log('🌐 API Base URL:', API_BASE_URL)

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 10000, // 10 second timeout - MANDATORY
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    // Log actual request URL on failure - MANDATORY
    console.log('📤 API Request:', config.method?.toUpperCase(), config.url)
    return config
  },
  (error) => {
    console.error('❌ Request Error:', error)
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    console.log('✅ API Response:', response.config.method?.toUpperCase(), response.config.url, response.status)
    return response
  },
  (error) => {
    // Log actual request URL on failure - MANDATORY
    console.error('❌ API Error:', error.config?.method?.toUpperCase(), error.config?.url)
    console.error('❌ Error Details:', {
      message: error.message,
      status: error.response?.status,
      data: error.response?.data,
      timeout: error.code === 'ECONNABORTED'
    })
    
    // Differentiate between error types - MANDATORY
    if (error.code === 'ECONNABORTED') {
      console.error('⏰ Request timeout exceeded')
      error.userMessage = 'Request timeout - please check your connection'
    } else if (error.response) {
      // Server responded with error status
      const status = error.response.status
      if (status >= 400 && status < 500) {
        console.error('🚫 Client Error (4xx):', status)
        error.userMessage = error.response.data?.message || 'Request failed'
      } else if (status >= 500) {
        console.error('💥 Server Error (5xx):', status)
        error.userMessage = 'Server error - please try again later'
      }
    } else if (error.request) {
      // Network error - no response received
      console.error('🌐 Network Error - Backend unreachable')
      error.userMessage = 'Cannot reach server - please check your connection'
    } else {
      console.error('❓ Unknown Error:', error.message)
      error.userMessage = 'An unexpected error occurred'
    }
    
    // Handle authentication errors
    if (error.response?.status === 401) {
      console.log('🔐 Authentication failed - redirecting to login')
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    
    return Promise.reject(error)
  }
)

export default api