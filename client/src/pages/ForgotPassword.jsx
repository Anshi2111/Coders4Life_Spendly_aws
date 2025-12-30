import { useState, useRef, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, Phone, Shield, Eye, EyeOff, CheckCircle, AlertCircle } from 'lucide-react'
import AppLogo from '../components/AppLogo'
import api from '../services/api'

function ForgotPassword() {
  const navigate = useNavigate()
  const [step, setStep] = useState(1) // 1: Phone, 2: OTP, 3: Reset Password
  const [phone, setPhone] = useState('')
  const [otp, setOtp] = useState(['', '', '', '', '', ''])
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [otpVerified, setOtpVerified] = useState(false)
  const [resendCooldown, setResendCooldown] = useState(0)
  
  const otpRefs = useRef([])

  // Resend cooldown timer
  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000)
      return () => clearTimeout(timer)
    }
  }, [resendCooldown])

  // Phone validation
  const validatePhone = (phoneNumber) => {
    const phoneRegex = /^[6-9]\d{9}$/
    return phoneRegex.test(phoneNumber)
  }

  // Password strength validation
  const validatePassword = (password) => {
    const minLength = password.length >= 8
    const hasNumber = /\d/.test(password)
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password)
    return { minLength, hasNumber, hasSpecial, isValid: minLength && hasNumber && hasSpecial }
  }

  // Step 1: Send OTP
  const handleSendOTP = async (e) => {
    e.preventDefault()
    
    if (!validatePhone(phone)) {
      setError('Please enter a valid 10-digit phone number')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await api.post('/auth/send-otp', { phone })
      
      if (response.data.success) {
        setStep(2)
        setResendCooldown(30)
      } else {
        setError(response.data.error || 'Failed to send OTP')
      }
    } catch (err) {
      console.error('Send OTP error:', err)
      if (err.response?.status === 404) {
        setError('Phone number not registered')
      } else {
        setError('Failed to send OTP. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  // Step 2: Verify OTP
  const handleVerifyOTP = async (e) => {
    e.preventDefault()
    
    const otpString = otp.join('')
    if (otpString.length !== 6) {
      setError('Please enter complete 6-digit OTP')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await api.post('/auth/verify-otp', { 
        phone, 
        otp: otpString 
      })
      
      if (response.data.success) {
        setOtpVerified(true)
        setStep(3)
        setOtp(['', '', '', '', '', '']) // Clear OTP from state
      } else {
        setError(response.data.error || 'Invalid OTP')
      }
    } catch (err) {
      console.error('Verify OTP error:', err)
      if (err.response?.status === 400) {
        setError('Invalid or expired OTP')
      } else {
        setError('Failed to verify OTP. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  // Step 3: Reset Password
  const handleResetPassword = async (e) => {
    e.preventDefault()
    
    if (!otpVerified) {
      setError('OTP verification required')
      return
    }

    const passwordValidation = validatePassword(newPassword)
    if (!passwordValidation.isValid) {
      setError('Password must be at least 8 characters with 1 number and 1 special character')
      return
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await api.post('/auth/reset-password', { 
        phone, 
        newPassword 
      })
      
      if (response.data.success) {
        // Clear sensitive state
        setPhone('')
        setNewPassword('')
        setConfirmPassword('')
        setOtpVerified(false)
        
        // Redirect to login with success message
        navigate('/login', { 
          state: { message: 'Password reset successful. Please login with your new password.' }
        })
      } else {
        setError(response.data.error || 'Failed to reset password')
      }
    } catch (err) {
      console.error('Reset password error:', err)
      setError('Failed to reset password. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // Resend OTP
  const handleResendOTP = async () => {
    if (resendCooldown > 0) return
    
    setLoading(true)
    setError('')
    setOtp(['', '', '', '', '', ''])

    try {
      const response = await api.post('/auth/send-otp', { phone })
      
      if (response.data.success) {
        setResendCooldown(30)
      } else {
        setError(response.data.error || 'Failed to resend OTP')
      }
    } catch (err) {
      console.error('Resend OTP error:', err)
      setError('Failed to resend OTP. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // OTP input handling
  const handleOtpChange = (index, value) => {
    if (!/^\d*$/.test(value)) return
    
    const newOtp = [...otp]
    newOtp[index] = value.slice(-1)
    setOtp(newOtp)
    setError('')

    // Auto focus next input
    if (value && index < 5) {
      otpRefs.current[index + 1]?.focus()
    }
  }

  const handleOtpKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      otpRefs.current[index - 1]?.focus()
    }
  }

  // Step 1: Phone Number Input
  if (step === 1) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <div className="flex justify-center mb-6">
              <AppLogo size="large" showImage={true} />
            </div>
            <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
              Forgot Password
            </h2>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              Enter your registered phone number to receive OTP
            </p>
          </div>

          <div className="card-gradient">
            <form className="space-y-6" onSubmit={handleSendOTP}>
              {error && (
                <div className="flex items-center space-x-2 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-xl">
                  <AlertCircle className="h-5 w-5 text-danger-500" />
                  <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
                </div>
              )}

              <div>
                <label htmlFor="phone" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Phone Number
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Phone className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="phone"
                    name="phone"
                    type="tel"
                    required
                    className="input w-full pl-12"
                    placeholder="9876543210"
                    value={phone}
                    onChange={(e) => {
                      const value = e.target.value.replace(/\D/g, '').slice(0, 10)
                      setPhone(value)
                      setError('')
                    }}
                    disabled={loading}
                  />
                </div>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Enter 10-digit mobile number without country code
                </p>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={loading || !phone}
                  className="btn-primary w-full flex items-center justify-center"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Sending OTP...
                    </>
                  ) : (
                    'Send OTP'
                  )}
                </button>
              </div>

              <div className="text-center">
                <Link 
                  to="/login" 
                  className="flex items-center justify-center space-x-2 text-sm text-primary-600 hover:text-primary-500 dark:text-primary-400 transition-colors"
                >
                  <ArrowLeft className="h-4 w-4" />
                  <span>Back to Login</span>
                </Link>
              </div>
            </form>
          </div>
        </div>
      </div>
    )
  }

  // Step 2: OTP Verification
  if (step === 2) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <div className="flex justify-center mb-6">
              <div className="bg-primary-100 dark:bg-primary-900/20 p-4 rounded-full">
                <Shield className="h-8 w-8 text-primary-600 dark:text-primary-400" />
              </div>
            </div>
            <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
              Verify OTP
            </h2>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              Enter the 6-digit code sent to +91 {phone}
            </p>
          </div>

          <div className="card-gradient">
            <form className="space-y-6" onSubmit={handleVerifyOTP}>
              {error && (
                <div className="flex items-center space-x-2 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-xl">
                  <AlertCircle className="h-5 w-5 text-danger-500" />
                  <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-4 text-center">
                  Enter OTP
                </label>
                <div className="flex justify-center space-x-3">
                  {otp.map((digit, index) => (
                    <input
                      key={index}
                      ref={(el) => otpRefs.current[index] = el}
                      type="text"
                      inputMode="numeric"
                      maxLength="1"
                      className="w-12 h-12 text-center text-lg font-bold border border-gray-300 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                      value={digit}
                      onChange={(e) => handleOtpChange(index, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(index, e)}
                      disabled={loading}
                    />
                  ))}
                </div>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={loading || otp.join('').length !== 6}
                  className="btn-primary w-full flex items-center justify-center"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Verifying...
                    </>
                  ) : (
                    'Verify OTP'
                  )}
                </button>
              </div>

              <div className="text-center">
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                  Didn't receive the code?
                </p>
                <button
                  type="button"
                  onClick={handleResendOTP}
                  disabled={resendCooldown > 0 || loading}
                  className="text-sm text-primary-600 hover:text-primary-500 dark:text-primary-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend OTP'}
                </button>
              </div>

              <div className="text-center">
                <button
                  type="button"
                  onClick={() => {
                    setStep(1)
                    setOtp(['', '', '', '', '', ''])
                    setError('')
                  }}
                  className="flex items-center justify-center space-x-2 text-sm text-gray-600 hover:text-gray-500 dark:text-gray-400 transition-colors mx-auto"
                >
                  <ArrowLeft className="h-4 w-4" />
                  <span>Change Phone Number</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    )
  }

  // Step 3: Reset Password
  const passwordValidation = validatePassword(newPassword)
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <div className="bg-green-100 dark:bg-green-900/20 p-4 rounded-full">
              <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
            </div>
          </div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Reset Password
          </h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Create a new secure password for your account
          </p>
        </div>

        <div className="card-gradient">
          <form className="space-y-6" onSubmit={handleResetPassword}>
            {error && (
              <div className="flex items-center space-x-2 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-xl">
                <AlertCircle className="h-5 w-5 text-danger-500" />
                <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
              </div>
            )}

            <div>
              <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                New Password
              </label>
              <div className="relative">
                <input
                  id="newPassword"
                  name="newPassword"
                  type={showPassword ? 'text' : 'password'}
                  required
                  className="input w-full pr-12"
                  placeholder="Enter new password"
                  value={newPassword}
                  onChange={(e) => {
                    setNewPassword(e.target.value)
                    setError('')
                  }}
                  disabled={loading}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-4 flex items-center"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={loading}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-gray-400" />
                  ) : (
                    <Eye className="h-5 w-5 text-gray-400" />
                  )}
                </button>
              </div>
              
              {/* Password strength indicator */}
              {newPassword && (
                <div className="mt-2 space-y-1">
                  <div className="flex items-center space-x-2 text-xs">
                    <div className={`w-2 h-2 rounded-full ${passwordValidation.minLength ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                    <span className={passwordValidation.minLength ? 'text-green-600' : 'text-gray-500'}>
                      At least 8 characters
                    </span>
                  </div>
                  <div className="flex items-center space-x-2 text-xs">
                    <div className={`w-2 h-2 rounded-full ${passwordValidation.hasNumber ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                    <span className={passwordValidation.hasNumber ? 'text-green-600' : 'text-gray-500'}>
                      At least 1 number
                    </span>
                  </div>
                  <div className="flex items-center space-x-2 text-xs">
                    <div className={`w-2 h-2 rounded-full ${passwordValidation.hasSpecial ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                    <span className={passwordValidation.hasSpecial ? 'text-green-600' : 'text-gray-500'}>
                      At least 1 special character
                    </span>
                  </div>
                </div>
              )}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Confirm Password
              </label>
              <div className="relative">
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  required
                  className="input w-full pr-12"
                  placeholder="Confirm new password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value)
                    setError('')
                  }}
                  disabled={loading}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-4 flex items-center"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  disabled={loading}
                >
                  {showConfirmPassword ? (
                    <EyeOff className="h-5 w-5 text-gray-400" />
                  ) : (
                    <Eye className="h-5 w-5 text-gray-400" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={loading || !passwordValidation.isValid || newPassword !== confirmPassword}
                className="btn-primary w-full flex items-center justify-center"
              >
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Resetting Password...
                  </>
                ) : (
                  'Reset Password'
                )}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

export default ForgotPassword