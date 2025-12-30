import React, { useState, useEffect } from 'react'
import { 
  Send, 
  X, 
  Camera, 
  CreditCard, 
  AlertCircle, 
  CheckCircle,
  Loader2,
  Wallet
} from 'lucide-react'
import { useBalance } from '../contexts/BalanceContext'
import QRScanner from './QRScanner'
import Toast from './Toast'
import api from '../services/api'

function QuickPayment({ isOpen, onClose, preSelectedCategory }) {
  const { 
    categories, 
    getCategoryById, 
    validatePayment, 
    updateCategoryBalance,
    addTransaction,
    loadData
  } = useBalance()

  // Form state
  const [formData, setFormData] = useState({
    amount: '',
    categoryId: '',
    upiId: '',
    merchantName: ''
  })

  // UI state
  const [paymentMethod, setPaymentMethod] = useState('manual') // 'manual' or 'qr'
  const [showQRScanner, setShowQRScanner] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [showPaymentApps, setShowPaymentApps] = useState(false)
  const [selectedPaymentApp, setSelectedPaymentApp] = useState('')
  const [toast, setToast] = useState(null)
  const [errors, setErrors] = useState({})

  // Payment apps configuration
  const paymentApps = [
    {
      id: 'phonepe',
      name: 'PhonePe',
      icon: '📱',
      color: 'from-purple-500 to-purple-600',
      scheme: 'phonepe://'
    },
    {
      id: 'googlepay',
      name: 'Google Pay',
      icon: '💳',
      color: 'from-blue-500 to-blue-600',
      scheme: 'tez://'
    },
    {
      id: 'paytm',
      name: 'Paytm',
      icon: '💰',
      color: 'from-indigo-500 to-indigo-600',
      scheme: 'paytmmp://'
    },
    {
      id: 'generic',
      name: 'Other UPI Apps',
      icon: '🏦',
      color: 'from-gray-500 to-gray-600',
      scheme: 'upi://'
    }
  ]

  // Default categories for fallback
  const defaultCategories = [
    { id: 'default-food', name: 'Food', balance: 5000, color: '#EF4444' },
    { id: 'default-rent', name: 'Rent', balance: 15000, color: '#3B82F6' },
    { id: 'default-travel', name: 'Travel', balance: 3000, color: '#8B5CF6' },
    { id: 'default-shopping', name: 'Shopping', balance: 7000, color: '#F59E0B' }
  ]

  // Get available categories (user categories + defaults if none exist)
  const availableCategories = categories?.length > 0 ? categories : defaultCategories

  // Reset form when modal opens/closes
  useEffect(() => {
    if (isOpen) {
      const initialCategory = preSelectedCategory || availableCategories[0]
      setFormData({
        amount: '',
        categoryId: initialCategory?.id || '',
        upiId: preSelectedCategory?.savedUpiId || '',
        merchantName: ''
      })
      setErrors({})
      setPaymentMethod('manual')
      setShowConfirmation(false)
      setShowPaymentApps(false)
      setSelectedPaymentApp('')
      setIsProcessing(false)
      setToast(null)
      
      // Clear any pending payment data
      sessionStorage.removeItem('pendingPayment')
      
      console.log('🔄 Modal opened - state reset')
    } else {
      // Reset all state when modal closes
      setShowConfirmation(false)
      setShowPaymentApps(false)
      setSelectedPaymentApp('')
      setIsProcessing(false)
      setToast(null)
      sessionStorage.removeItem('pendingPayment')
      
      console.log('🔄 Modal closed - state reset')
    }
  }, [isOpen, availableCategories, preSelectedCategory])

  const showToast = (message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  const validateForm = () => {
    const newErrors = {}

    // Validate amount
    const amount = parseFloat(formData.amount)
    if (!formData.amount || isNaN(amount) || amount <= 0) {
      newErrors.amount = 'Enter a valid amount'
    }

    // Validate category
    if (!formData.categoryId) {
      newErrors.categoryId = 'Select a category'
    }

    // Validate UPI ID
    if (!formData.upiId) {
      newErrors.upiId = 'Enter UPI ID'
    } else if (!/^[\w.-]+@[\w.-]+$/.test(formData.upiId)) {
      newErrors.upiId = 'Invalid UPI ID format'
    }

    // Validate balance
    if (formData.categoryId && formData.amount) {
      const category = getCategoryById(formData.categoryId) || 
        defaultCategories.find(c => c.id === formData.categoryId)
      
      if (category) {
        const balance = category.current_balance || category.balance || 0
        if (amount > balance) {
          newErrors.amount = `Insufficient balance. Available: ₹${balance.toLocaleString('en-IN')}`
        }
      }
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }))
    
    // Clear specific error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }))
    }
  }

  const handleQRScan = (qrData) => {
    try {
      if (qrData?.upiId) {
        setFormData(prev => ({
          ...prev,
          upiId: qrData.upiId,
          merchantName: qrData.merchantName || ''
        }))
        showToast('QR code scanned successfully!')
      }
    } catch (error) {
      console.error('❌ QR scan error:', error)
      showToast('Failed to process QR code', 'error')
    }
    setShowQRScanner(false)
  }

  const generateUPIUrl = (appScheme = 'upi://') => {
    const { amount, upiId, merchantName, categoryId } = formData
    const category = getCategoryById(categoryId) || 
      defaultCategories.find(c => c.id === categoryId)
    
    const params = new URLSearchParams({
      pa: upiId,
      pn: merchantName || 'Merchant',
      am: amount,
      cu: 'INR',
      tn: `Payment from ${category?.name || 'Spendly'}`
    })

    return `${appScheme}pay?${params.toString()}`
  }

  const handlePayment = async () => {
    if (!validateForm()) return

    // Show payment app selection
    setShowPaymentApps(true)
  }

  const handlePaymentAppSelection = async (app) => {
    try {
      setIsProcessing(true)
      setSelectedPaymentApp(app.id)
      
      // Generate UPI URL with selected app scheme
      const upiUrl = generateUPIUrl(app.scheme)
      console.log(`🚀 Redirecting to ${app.name}:`, upiUrl)
      
      // Store payment data for confirmation (with timestamp)
      const paymentData = {
        ...formData,
        paymentApp: app.name,
        timestamp: Date.now()
      }
      sessionStorage.setItem('pendingPayment', JSON.stringify(paymentData))
      console.log('💾 Stored pending payment data:', paymentData)

      // Hide app selection and show confirmation
      setShowPaymentApps(false)
      setIsProcessing(false)
      setShowConfirmation(true)

      // Try to redirect to selected UPI app
      try {
        window.location.href = upiUrl
      } catch (redirectError) {
        console.log(`${app.name} redirect failed, continuing with manual confirmation`)
      }

    } catch (error) {
      console.error('❌ Payment error:', error)
      showToast('Failed to initiate payment', 'error')
      setIsProcessing(false)
      setShowPaymentApps(false)
    }
  }

  const handlePaymentConfirmation = async (success) => {
    console.log('🔄 Payment confirmation:', success ? 'SUCCESS' : 'FAILED')
    
    try {
      setIsProcessing(true)
      
      if (success) {
        const amount = parseFloat(formData.amount)
        const category = getCategoryById(formData.categoryId) || 
          defaultCategories.find(c => c.id === formData.categoryId)

        // Create transaction record with pending status first
        const transactionData = {
          category_id: formData.categoryId.startsWith('default-') ? null : formData.categoryId,
          amount,
          merchant_name: formData.merchantName || 'UPI Payment',
          merchant_upi: formData.upiId,
          note: `Payment via ${formData.upiId}`
        }

        // Save to backend if real category
        if (!formData.categoryId.startsWith('default-')) {
          try {
            console.log('💾 Creating transaction in backend...')
            
            // Step 1: Create transaction (status: pending)
            const createResponse = await api.post('/transactions', transactionData)
            console.log('✅ Transaction created:', createResponse.data)
            
            const transactionId = createResponse.data.transaction?.id
            if (!transactionId) {
              throw new Error('No transaction ID returned')
            }
            
            // Step 2: Update status to success (this deducts balance)
            console.log('💾 Updating transaction status to success...')
            await api.put(`/transactions/${transactionId}/status`, { status: 'success' })
            console.log('✅ Transaction status updated to success')
            
            // Step 3: Refresh data
            await loadData()
            showToast(`Payment of ₹${amount.toLocaleString('en-IN')} completed successfully!`)
            console.log('✅ Payment process completed successfully')
            
          } catch (apiError) {
            console.error('❌ API Error:', apiError)
            const errorMsg = apiError.response?.data?.message || apiError.userMessage || 'Failed to process payment'
            showToast(errorMsg, 'error')
            return // Don't close modal on error
          }
        } else {
          // For default categories, just add to local state
          addTransaction({
            id: `TXN${Date.now()}`,
            ...transactionData,
            category_name: category?.name || 'Unknown',
            status: 'success',
            created_at: new Date().toISOString()
          })
          showToast(`Payment of ₹${amount.toLocaleString('en-IN')} completed successfully!`)
          console.log('✅ Transaction added to local state')
        }
      } else {
        showToast('Payment was cancelled or failed', 'info')
      }

      // Clear pending payment
      sessionStorage.removeItem('pendingPayment')
      
      // Close modal after showing toast
      setTimeout(() => {
        setShowConfirmation(false)
        onClose()
      }, success ? 1500 : 500)

    } catch (error) {
      console.error('❌ Confirmation error:', error)
      showToast('Failed to process payment confirmation', 'error')
    } finally {
      setIsProcessing(false)
    }
  }

  // Check for pending payment on component mount
  useEffect(() => {
    if (!isOpen) return
    
    const pendingPayment = sessionStorage.getItem('pendingPayment')
    if (pendingPayment) {
      try {
        const paymentData = JSON.parse(pendingPayment)
        console.log('🔍 Found pending payment:', paymentData)
        
        // Check if payment is recent (within 5 minutes) and matches current form
        const isRecent = Date.now() - paymentData.timestamp < 5 * 60 * 1000
        const matchesCurrentPayment = 
          paymentData.amount === formData.amount &&
          paymentData.categoryId === formData.categoryId &&
          paymentData.upiId === formData.upiId
        
        if (isRecent && matchesCurrentPayment) {
          console.log('✅ Restoring pending payment confirmation')
          setFormData(prev => ({
            ...prev,
            paymentApp: paymentData.paymentApp || ''
          }))
          setShowConfirmation(true)
        } else {
          console.log('🗑️ Clearing old/mismatched pending payment')
          sessionStorage.removeItem('pendingPayment')
        }
      } catch (error) {
        console.error('❌ Pending payment error:', error)
        sessionStorage.removeItem('pendingPayment')
      }
    }
  }, [isOpen, formData.amount, formData.categoryId, formData.upiId])

  const selectedCategory = getCategoryById(formData.categoryId) || 
    defaultCategories.find(c => c.id === formData.categoryId)
  const categoryBalance = selectedCategory?.current_balance || selectedCategory?.balance || 0

  if (!isOpen) return null

  return (
    <>
      <div className="fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4">
        <div className="bg-white dark:bg-gray-800 rounded-2xl max-w-md w-full max-h-[90vh] overflow-y-auto">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center space-x-2">
              <Send className="h-5 w-5 text-primary-500" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                Quick Payment
              </h3>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Payment App Selection Modal */}
          {showPaymentApps && (
            <div className="p-6">
              <div className="text-center mb-6">
                <div className="bg-primary-100 dark:bg-primary-900/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Wallet className="h-8 w-8 text-primary-600 dark:text-primary-400" />
                </div>
                <h4 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Choose Payment App
                </h4>
                <p className="text-gray-600 dark:text-gray-400 text-sm">
                  Select your preferred UPI app to complete the payment
                </p>
                
                {/* Payment Summary */}
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 mt-4 mb-6">
                  <div className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                    <div className="flex justify-between">
                      <span>Amount:</span>
                      <span className="font-semibold text-gray-900 dark:text-gray-100">₹{formData.amount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>To:</span>
                      <span className="font-semibold text-gray-900 dark:text-gray-100">{formData.merchantName || formData.upiId}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Category:</span>
                      <span className="font-semibold text-gray-900 dark:text-gray-100">{selectedCategory?.name}</span>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Payment App Options */}
              <div className="grid grid-cols-2 gap-3 mb-6">
                {paymentApps.map((app) => (
                  <button
                    key={app.id}
                    onClick={() => handlePaymentAppSelection(app)}
                    disabled={isProcessing && selectedPaymentApp === app.id}
                    className={`relative p-4 rounded-xl border-2 transition-all duration-200 ${
                      isProcessing && selectedPaymentApp === app.id
                        ? 'border-gray-300 bg-gray-100 cursor-not-allowed'
                        : 'border-gray-200 hover:border-gray-300 hover:shadow-md active:scale-95'
                    }`}
                  >
                    <div className={`w-full h-20 rounded-lg bg-gradient-to-br ${app.color} flex items-center justify-center mb-3`}>
                      <span className="text-3xl">{app.icon}</span>
                    </div>
                    <div className="text-center">
                      <h5 className="font-semibold text-gray-900 dark:text-gray-100 text-sm">
                        {app.name}
                      </h5>
                      {isProcessing && selectedPaymentApp === app.id && (
                        <div className="flex items-center justify-center mt-2">
                          <Loader2 className="h-3 w-3 animate-spin text-gray-500" />
                          <span className="text-xs text-gray-500 ml-1">Opening...</span>
                        </div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
              
              {/* Back Button */}
              <button
                onClick={() => setShowPaymentApps(false)}
                disabled={isProcessing}
                className="w-full py-3 px-4 rounded-lg border-2 border-gray-300 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                ← Back to Payment Details
              </button>
            </div>
          )}

          {/* Confirmation Modal */}
          {showConfirmation && (
            <div className="p-6">
              <div className="text-center mb-6">
                <div className="bg-secondary-100 dark:bg-secondary-900/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                  <CheckCircle className="h-8 w-8 text-secondary-600 dark:text-secondary-400" />
                </div>
                <h4 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-3">
                  Confirm Payment Status
                </h4>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 mb-4">
                  <div className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                    <div className="flex justify-between">
                      <span>Amount:</span>
                      <span className="font-semibold text-gray-900 dark:text-gray-100">₹{formData.amount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>To:</span>
                      <span className="font-semibold text-gray-900 dark:text-gray-100">{formData.merchantName || formData.upiId}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Category:</span>
                      <span className="font-semibold text-gray-900 dark:text-gray-100">{selectedCategory?.name}</span>
                    </div>
                    {formData.paymentApp && (
                      <div className="flex justify-between">
                        <span>Payment App:</span>
                        <span className="font-semibold text-gray-900 dark:text-gray-100">{formData.paymentApp}</span>
                      </div>
                    )}
                  </div>
                </div>
                <p className="text-gray-600 dark:text-gray-400 text-sm">
                  Please confirm if the payment was completed successfully in your UPI app.
                </p>
              </div>
              
              <div className="space-y-3">
                {/* Success Button */}
                <button
                  onClick={async () => {
                    console.log('🔥 BUTTON CLICKED - Starting payment confirmation')
                    
                    if (isProcessing) {
                      console.log('⚠️ Already processing, ignoring click')
                      return
                    }
                    
                    try {
                      setIsProcessing(true)
                      console.log('💰 Processing payment confirmation...')
                      
                      const amount = parseFloat(formData.amount)
                      console.log('💵 Amount:', amount)
                      console.log('🏷️ Category ID:', formData.categoryId)
                      console.log('🏪 Merchant UPI:', formData.upiId)
                      
                      // Create transaction data
                      const transactionData = {
                        category_id: formData.categoryId,
                        amount: amount,
                        merchant_name: formData.merchantName || 'UPI Payment',
                        merchant_upi: formData.upiId,
                        note: `Payment via ${formData.upiId}`
                      }
                      
                      console.log('📝 Transaction data:', transactionData)
                      
                      // Step 1: Create transaction
                      console.log('🚀 Creating transaction...')
                      const createResponse = await api.post('/transactions', transactionData)
                      console.log('✅ Create response:', createResponse.data)
                      
                      const transactionId = createResponse.data.transaction?.id
                      console.log('🆔 Transaction ID:', transactionId)
                      
                      if (!transactionId) {
                        throw new Error('No transaction ID returned')
                      }
                      
                      // Step 2: Update to success
                      console.log('🔄 Updating status to success...')
                      const updateResponse = await api.put(`/transactions/${transactionId}/status`, { status: 'success' })
                      console.log('✅ Update response:', updateResponse.data)
                      
                      // Step 3: Refresh data
                      console.log('🔄 Refreshing data...')
                      await loadData()
                      
                      // Show success message
                      showToast(`Payment of ₹${amount.toLocaleString('en-IN')} completed successfully!`)
                      console.log('🎉 Payment completed successfully!')
                      
                      // Close modal
                      setTimeout(() => {
                        setShowConfirmation(false)
                        onClose()
                      }, 1500)
                      
                    } catch (error) {
                      console.error('❌ Payment error:', error)
                      console.error('❌ Error details:', {
                        message: error.message,
                        response: error.response?.data,
                        status: error.response?.status
                      })
                      
                      const errorMsg = error.response?.data?.message || error.userMessage || 'Failed to process payment'
                      showToast(errorMsg, 'error')
                    } finally {
                      setIsProcessing(false)
                      console.log('🏁 Payment processing finished')
                    }
                  }}
                  disabled={isProcessing}
                  className={`w-full py-3 px-4 rounded-lg text-center transition-all ${
                    isProcessing 
                      ? 'bg-gray-400 cursor-not-allowed' 
                      : 'bg-gradient-to-r from-green-500 to-blue-500 hover:from-green-600 hover:to-blue-600'
                  }`}
                  style={{
                    background: isProcessing ? '#9CA3AF' : 'linear-gradient(135deg, #10B981 0%, #3B82F6 100%)',
                    color: 'white',
                    fontWeight: '600',
                    fontSize: '16px'
                  }}
                >
                  {isProcessing ? (
                    <div className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Processing...
                    </div>
                  ) : (
                    '✅ Yes, Payment Successful'
                  )}
                </button>
                
                {/* Failed Button */}
                <button
                  onClick={() => handlePaymentConfirmation(false)}
                  disabled={isProcessing}
                  className="w-full py-3 px-4 rounded-lg border-2 border-gray-300 text-center hover:bg-gray-50 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{
                    color: '#374151',
                    fontWeight: '500',
                    fontSize: '16px'
                  }}
                >
                  ❌ No, Payment Failed
                </button>
                
                {/* Cancel Button */}
                <button
                  onClick={() => {
                    if (isProcessing) return;
                    console.log('🔄 CANCEL CLICKED');
                    setShowConfirmation(false);
                  }}
                  disabled={isProcessing}
                  className="w-full py-2 text-center text-gray-500 hover:text-gray-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ fontSize: '14px' }}
                >
                  Cancel & Try Again
                </button>
              </div>
            </div>
          )}

          {/* Payment Form */}
          {!showConfirmation && !showPaymentApps && (
            <div className="p-6 space-y-6">
              {/* Amount & Category */}
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Amount (₹)
                  </label>
                  <input
                    type="number"
                    value={formData.amount}
                    onChange={(e) => handleInputChange('amount', e.target.value)}
                    className={`input w-full ${errors.amount ? 'border-danger-500' : ''}`}
                    placeholder="Enter amount"
                    min="1"
                    step="1"
                  />
                  {errors.amount && (
                    <p className="text-sm text-danger-600 mt-1">{errors.amount}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Budget Category
                  </label>
                  <select
                    value={formData.categoryId}
                    onChange={(e) => handleInputChange('categoryId', e.target.value)}
                    disabled={!!preSelectedCategory}
                    className={`input w-full ${errors.categoryId ? 'border-danger-500' : ''} ${preSelectedCategory ? 'bg-gray-100 dark:bg-gray-700 cursor-not-allowed' : ''}`}
                  >
                    <option value="">Select category</option>
                    {availableCategories.map(category => (
                      <option key={category.id} value={category.id}>
                        {category.name} - ₹{(category.current_balance || category.balance || 0).toLocaleString('en-IN')}
                      </option>
                    ))}
                  </select>
                  {errors.categoryId && (
                    <p className="text-sm text-danger-600 mt-1">{errors.categoryId}</p>
                  )}
                  
                  {preSelectedCategory && (
                    <p className="text-sm text-secondary-600 dark:text-secondary-400 mt-1">
                      ✓ Category pre-selected from Home page
                    </p>
                  )}
                  
                  {formData.categoryId && (
                    <div className="mt-2 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600 dark:text-gray-400">Available Balance:</span>
                        <span className="font-semibold text-gray-900 dark:text-gray-100">
                          ₹{categoryBalance.toLocaleString('en-IN')}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Payment Method Tabs */}
              <div>
                <div className="flex space-x-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1 mb-4">
                  <button
                    onClick={() => setPaymentMethod('manual')}
                    className={`flex-1 py-2 px-3 text-sm rounded-md transition-colors ${
                      paymentMethod === 'manual'
                        ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-gray-100 shadow-sm'
                        : 'text-gray-600 dark:text-gray-400'
                    }`}
                  >
                    <CreditCard className="h-4 w-4 inline mr-2" />
                    Enter UPI ID
                  </button>
                  <button
                    onClick={() => setPaymentMethod('qr')}
                    className={`flex-1 py-2 px-3 text-sm rounded-md transition-colors ${
                      paymentMethod === 'qr'
                        ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-gray-100 shadow-sm'
                        : 'text-gray-600 dark:text-gray-400'
                    }`}
                  >
                    <Camera className="h-4 w-4 inline mr-2" />
                    Scan QR Code
                  </button>
                </div>

                {/* Manual UPI ID Entry */}
                {paymentMethod === 'manual' && (
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        UPI ID
                      </label>
                      <input
                        type="text"
                        value={formData.upiId}
                        onChange={(e) => handleInputChange('upiId', e.target.value)}
                        className={`input w-full ${errors.upiId ? 'border-danger-500' : ''}`}
                        placeholder="merchant@paytm"
                      />
                      {errors.upiId && (
                        <p className="text-sm text-danger-600 mt-1">{errors.upiId}</p>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Merchant Name (Optional)
                      </label>
                      <input
                        type="text"
                        value={formData.merchantName}
                        onChange={(e) => handleInputChange('merchantName', e.target.value)}
                        className="input w-full"
                        placeholder="Merchant Name"
                      />
                    </div>
                  </div>
                )}

                {/* QR Code Scanner */}
                {paymentMethod === 'qr' && (
                  <div className="text-center py-8">
                    <Camera className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                    <p className="text-gray-600 dark:text-gray-400 mb-4">
                      Scan a UPI QR code to auto-fill payment details
                    </p>
                    <button
                      onClick={() => setShowQRScanner(true)}
                      className="btn-primary"
                    >
                      <Camera className="h-4 w-4 mr-2" />
                      Open Camera
                    </button>
                    
                    {formData.upiId && (
                      <div className="mt-4 p-3 bg-secondary-50 dark:bg-secondary-900/20 rounded-lg">
                        <p className="text-sm text-secondary-700 dark:text-secondary-300">
                          ✅ Scanned: {formData.upiId}
                        </p>
                        {formData.merchantName && (
                          <p className="text-sm text-secondary-600 dark:text-secondary-400">
                            {formData.merchantName}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Payment Button */}
              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={handlePayment}
                  disabled={isProcessing || !formData.amount || !formData.categoryId || !formData.upiId}
                  className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isProcessing ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <Wallet className="h-4 w-4 mr-2" />
                      Choose Payment App - ₹{formData.amount || '0'}
                    </>
                  )}
                </button>
                
                <p className="text-xs text-gray-500 dark:text-gray-400 text-center mt-2">
                  Select your preferred UPI app to complete the payment
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* QR Scanner Modal */}
      <QRScanner
        isOpen={showQRScanner}
        onClose={() => setShowQRScanner(false)}
        onScan={handleQRScan}
      />

      {/* Toast Notifications */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}
    </>
  )
}

export default QuickPayment