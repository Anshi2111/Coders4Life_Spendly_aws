import React, { useState } from 'react'
import { 
  User, 
  Mail, 
  DollarSign, 
  Save, 
  AlertCircle,
  CheckCircle,
  Shield,
  Info
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import api from '../services/api'

function Profile() {
  const { user, updateUser, logout } = useAuth()
  const [formData, setFormData] = useState({
    name: user?.name || '',
    salary: user?.salary || ''
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: value
    }))
    // Clear messages when user starts typing
    if (error) setError('')
    if (success) setSuccess('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!formData.name.trim()) {
      setError('Name is required')
      return
    }
    
    if (formData.salary && parseFloat(formData.salary) <= 0) {
      setError('Salary must be a positive number')
      return
    }

    setLoading(true)
    setError('')
    setSuccess('')

    try {
      // Update name if changed
      if (formData.name !== user?.name) {
        await api.put('/user/profile', { name: formData.name.trim() })
        updateUser({ name: formData.name.trim() })
      }
      
      // Update salary if changed
      if (formData.salary && parseFloat(formData.salary) !== user?.salary) {
        await api.put('/user/salary', { salary: parseFloat(formData.salary) })
        updateUser({ salary: parseFloat(formData.salary) })
      }
      
      setSuccess('Profile updated successfully!')
    } catch (err) {
      console.error('❌ Failed to update profile:', err)
      setError(err.response?.data?.message || err.userMessage || 'Failed to update profile')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
          Profile Settings
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Manage your account information and preferences
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Profile Form */}
        <div className="lg:col-span-2">
          <div className="card">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-6">
              Personal Information
            </h2>

            {error && (
              <div className="mb-6 flex items-center space-x-2 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
                <AlertCircle className="h-5 w-5 text-danger-500" />
                <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
              </div>
            )}

            {success && (
              <div className="mb-6 flex items-center space-x-2 p-4 bg-secondary-50 dark:bg-secondary-900/20 border border-secondary-200 dark:border-secondary-800 rounded-lg">
                <CheckCircle className="h-5 w-5 text-secondary-500" />
                <p className="text-sm text-secondary-700 dark:text-secondary-400">{success}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  <Mail className="h-4 w-4 inline mr-2" />
                  Email Address
                </label>
                <input
                  type="email"
                  value={user?.email || ''}
                  className="input w-full bg-gray-50 dark:bg-gray-700"
                  disabled
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Email cannot be changed for security reasons
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  <User className="h-4 w-4 inline mr-2" />
                  Full Name
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  className="input w-full"
                  placeholder="Enter your full name"
                  disabled={loading}
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  <DollarSign className="h-4 w-4 inline mr-2" />
                  Monthly Salary (₹)
                </label>
                <input
                  type="number"
                  name="salary"
                  value={formData.salary}
                  onChange={handleChange}
                  className="input w-full"
                  placeholder="Enter your monthly salary"
                  min="0"
                  step="0.01"
                  disabled={loading}
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Used to calculate category allocations based on percentages
                </p>
              </div>

              <div className="flex items-center justify-end space-x-3 pt-4">
                <button
                  type="submit"
                  disabled={loading}
                  className="btn-primary flex items-center space-x-2"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                      <span>Saving...</span>
                    </>
                  ) : (
                    <>
                      <Save className="h-4 w-4" />
                      <span>Save Changes</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Account Info */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              Account Information
            </h3>
            
            <div className="space-y-3">
              <div className="flex items-center justify-center w-16 h-16 bg-primary-100 dark:bg-primary-900/20 rounded-full mx-auto mb-4">
                <span className="text-2xl font-bold text-primary-600 dark:text-primary-400">
                  {user?.name?.charAt(0)?.toUpperCase() || user?.email?.charAt(0)?.toUpperCase() || 'U'}
                </span>
              </div>
              
              <div className="text-center">
                <p className="font-medium text-gray-900 dark:text-gray-100">
                  {user?.name || 'User'}
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {user?.email}
                </p>
              </div>
            </div>
          </div>

          {/* Security Notice */}
          <div className="card">
            <div className="flex items-start space-x-3">
              <Shield className="h-5 w-5 text-primary-500 mt-0.5" />
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Security & Privacy
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  We never store your bank details or UPI credentials. All payments are handled securely through your UPI app.
                </p>
              </div>
            </div>
          </div>

          {/* UPI Disclaimer */}
          <div className="card">
            <div className="flex items-start space-x-3">
              <Info className="h-5 w-5 text-yellow-500 mt-0.5" />
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  UPI Payments
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Payments are processed through your installed UPI apps (Google Pay, PhonePe, etc.). We only track transaction status for budget management.
                </p>
              </div>
            </div>
          </div>

          {/* Logout */}
          <div className="card">
            <button
              onClick={logout}
              className="btn-danger w-full"
            >
              Sign Out
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Profile