import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Eye, EyeOff, AlertCircle, CheckCircle } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import AppLogo from '../components/AppLogo'

function Login() {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  })
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMessage, setSuccessMessage] = useState('')

  const { login } = useAuth()
  const location = useLocation()

  // Check for success message from forgot password flow
  useEffect(() => {
    if (location.state?.message) {
      setSuccessMessage(location.state.message)
      // Clear the message from location state
      window.history.replaceState({}, document.title)
    }
  }, [location.state])

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: value
    }))
    // Clear messages when user starts typing
    if (error) setError('')
    if (successMessage) setSuccessMessage('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!formData.email || !formData.password) {
      setError('Please fill in all fields')
      return
    }

    setIsLoading(true)
    setError('')
    setSuccessMessage('')

    try {
      const result = await login(formData.email, formData.password)
      
      if (!result.success) {
        setError(result.error || 'Login failed')
      }
      // Success is handled by AuthContext redirect
    } catch (err) {
      console.error('❌ Login error:', err)
      setError(err.userMessage || 'Login failed. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <AppLogo size="large" showImage={true} />
          </div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Welcome back
          </h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Sign in to your account to manage your finances
          </p>
        </div>

        {/* Form */}
        <div className="card-gradient">
          <form className="space-y-6" onSubmit={handleSubmit}>
            {error && (
              <div className="flex items-center space-x-2 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-xl">
                <AlertCircle className="h-5 w-5 text-danger-500" />
                <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
              </div>
            )}

            {successMessage && (
              <div className="flex items-center space-x-2 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-xl">
                <CheckCircle className="h-5 w-5 text-green-500" />
                <p className="text-sm text-green-700 dark:text-green-400">{successMessage}</p>
              </div>
            )}

            <div className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Email Address
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className="input w-full"
                  placeholder="Enter your email"
                  value={formData.email}
                  onChange={handleChange}
                  disabled={isLoading}
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    className="input w-full pr-12"
                    placeholder="Enter your password"
                    value={formData.password}
                    onChange={handleChange}
                    disabled={isLoading}
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-4 flex items-center"
                    onClick={() => setShowPassword(!showPassword)}
                    disabled={isLoading}
                  >
                    {showPassword ? (
                      <EyeOff className="h-5 w-5 text-gray-400" />
                    ) : (
                      <Eye className="h-5 w-5 text-gray-400" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="text-sm">
                <Link 
                  to="/forgot-password" 
                  className="font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400 transition-colors"
                >
                  Forgot your password?
                </Link>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="btn-primary w-full flex items-center justify-center"
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Signing in...
                  </>
                ) : (
                  'Sign In'
                )}
              </button>
            </div>

            <div className="text-center">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Don't have an account?{' '}
                <Link 
                  to="/register" 
                  className="font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400 transition-colors"
                >
                  Sign up here
                </Link>
              </p>
            </div>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center text-xs text-gray-500 dark:text-gray-400 space-y-2">
          <p>By signing in, you agree to our</p>
          <div className="space-x-4">
            <Link to="/terms" className="hover:text-primary-500 transition-colors">Terms of Service</Link>
            <span>•</span>
            <Link to="/privacy" className="hover:text-primary-500 transition-colors">Privacy Policy</Link>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Login