import React, { useState, useEffect } from 'react'
import { 
  Wallet, 
  Plus, 
  QrCode, 
  Send, 
  TrendingUp, 
  AlertCircle,
  RefreshCw,
  Eye,
  EyeOff,
  PieChart,
  BarChart3,
  Calendar,
  Target
} from 'lucide-react'
import { 
  PieChart as RechartsPieChart, 
  Cell, 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend,
  LineChart,
  Line,
  Pie
} from 'recharts'
import { useAuth } from '../contexts/AuthContext'
import { useBalance } from '../contexts/BalanceContext'
import QRScanner from '../components/QRScanner'
import Toast from '../components/Toast'
import api from '../services/api'

function Dashboard() {
  const { user } = useAuth()
  const { 
    categories, 
    transactions, 
    loading, 
    error, 
    totalBalance, 
    totalSpent, 
    totalBudget,
    loadData,
    validatePayment,
    updateCategoryBalance,
    addTransaction,
    setError
  } = useBalance()
  
  const [showQRScanner, setShowQRScanner] = useState(false)
  const [showBalances, setShowBalances] = useState(true)
  const [analyticsView, setAnalyticsView] = useState('overview') // overview, spending, trends
  const [toast, setToast] = useState(null)
  
  // Quick payment form
  const [paymentForm, setPaymentForm] = useState({
    amount: '',
    category_id: '',
    merchant_upi: '',
    merchant_name: '',
    note: ''
  })
  const [paymentLoading, setPaymentLoading] = useState(false)
  const [paymentError, setPaymentError] = useState('')

  // Default categories for budget planning
  const defaultCategories = [
    { name: 'Food & Dining', percentage: 25, color: '#EF4444', icon: '🍽️' },
    { name: 'Transportation', percentage: 15, color: '#3B82F6', icon: '🚗' },
    { name: 'Entertainment', percentage: 10, color: '#8B5CF6', icon: '🎬' },
    { name: 'Shopping', percentage: 15, color: '#F59E0B', icon: '🛍️' },
    { name: 'Bills & Utilities', percentage: 20, color: '#10B981', icon: '💡' },
    { name: 'Healthcare', percentage: 5, color: '#EC4899', icon: '🏥' },
    { name: 'Savings', percentage: 10, color: '#6B7280', icon: '💰' }
  ]

  useEffect(() => {
    // Data is automatically loaded by BalanceContext
  }, [])

  const showToast = (message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  const createDefaultCategories = async () => {
    if (!user?.salary) {
      setError('Please set your salary in Profile first')
      return
    }

    try {
      // Use bulk create endpoint
      await api.post('/categories/bulk', {
        categories: defaultCategories
      })
      
      // Recalculate balances after creating categories
      await api.post('/categories/recalculate')
      await loadData()
      setError('')
      showToast('Default categories created successfully!')
    } catch (err) {
      console.error('❌ Failed to create default categories:', err)
      setError(err.response?.data?.message || err.userMessage || 'Failed to create default categories')
    }
  }

  // Analytics data preparation
  const getSpendingData = () => {
    const categorySpending = {}
    
    transactions.filter(t => t.status === 'success').forEach(transaction => {
      const categoryName = transaction.category_name || 'Unknown'
      categorySpending[categoryName] = (categorySpending[categoryName] || 0) + transaction.amount
    })
    
    return Object.entries(categorySpending).map(([name, amount]) => ({
      name,
      amount,
      percentage: ((amount / Object.values(categorySpending).reduce((a, b) => a + b, 0)) * 100).toFixed(1)
    }))
  }

  const getBudgetVsSpendingData = () => {
    const spendingByCategory = {}
    
    transactions.filter(t => t.status === 'success').forEach(transaction => {
      const categoryName = transaction.category_name || 'Unknown'
      spendingByCategory[categoryName] = (spendingByCategory[categoryName] || 0) + transaction.amount
    })
    
    return categories.map(category => ({
      name: category.name,
      budget: category.current_balance + (spendingByCategory[category.name] || 0),
      spent: spendingByCategory[category.name] || 0,
      remaining: category.current_balance,
      color: category.color
    }))
  }

  const getMonthlyTrends = () => {
    const monthlyData = {}
    
    transactions.filter(t => t.status === 'success').forEach(transaction => {
      const date = new Date(transaction.created_at)
      const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
      
      if (!monthlyData[monthKey]) {
        monthlyData[monthKey] = { month: monthKey, amount: 0, count: 0 }
      }
      
      monthlyData[monthKey].amount += transaction.amount
      monthlyData[monthKey].count += 1
    })
    
    return Object.values(monthlyData).sort((a, b) => a.month.localeCompare(b.month))
  }

  const CHART_COLORS = ['#EF4444', '#3B82F6', '#8B5CF6', '#F59E0B', '#10B981', '#EC4899', '#6B7280', '#14B8A6', '#F97316', '#84CC16']

  const handlePaymentFormChange = (e) => {
    const { name, value } = e.target
    setPaymentForm(prev => ({
      ...prev,
      [name]: value
    }))
    if (paymentError) setPaymentError('')
  }

  const handleQRScan = (qrData) => {
    setPaymentForm(prev => ({
      ...prev,
      merchant_upi: qrData.upiId || '',
      merchant_name: qrData.merchantName || '',
      amount: qrData.amount || prev.amount,
      note: qrData.note || prev.note
    }))
  }

  const validatePaymentForm = () => {
    if (!paymentForm.amount || parseFloat(paymentForm.amount) <= 0) {
      setPaymentError('Please enter a valid amount')
      return false
    }
    
    if (!paymentForm.category_id) {
      setPaymentError('Please select a category')
      return false
    }
    
    if (!paymentForm.merchant_upi) {
      setPaymentError('Please enter merchant UPI ID or scan QR code')
      return false
    }
    
    // Use BalanceContext validation
    const validation = validatePayment(paymentForm.category_id, parseFloat(paymentForm.amount))
    if (!validation.valid) {
      setPaymentError(validation.error)
      return false
    }
    
    return true
  }

  const handlePayment = async (e) => {
    e.preventDefault()
    
    if (!validatePaymentForm()) {
      return
    }

    setPaymentLoading(true)
    setPaymentError('')

    try {
      const amount = parseFloat(paymentForm.amount)
      const categoryId = paymentForm.category_id
      
      // Optimistic update - deduct balance immediately
      const category = categories.find(cat => cat.id.toString() === categoryId)
      if (category) {
        updateCategoryBalance(categoryId, category.current_balance - amount)
      }
      
      const response = await api.post('/transactions', {
        ...paymentForm,
        amount
      })
      
      const transaction = response.data.transaction
      
      // Add transaction to context
      addTransaction(transaction)
      
      const { upi_url } = transaction
      
      // Show success message
      showToast(`₹${amount.toLocaleString('en-IN')} payment initiated from ${category?.name}`)
      
      // Reset form
      setPaymentForm({
        amount: '',
        category_id: '',
        merchant_upi: '',
        merchant_name: '',
        note: ''
      })
      
      // Redirect to UPI app
      window.location.href = upi_url
      
    } catch (err) {
      console.error('❌ Payment failed:', err)
      setPaymentError(err.response?.data?.message || err.userMessage || 'Payment failed')
      
      // Revert optimistic update on error
      await loadData()
    } finally {
      setPaymentLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </div>
    )
  }

  const totalSpentThisMonth = transactions.filter(t => t.status === 'success').reduce((sum, t) => sum + t.amount, 0)
  const selectedCategory = categories.find(cat => cat.id.toString() === paymentForm.category_id)

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            Welcome back, {user?.name || 'User'}!
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Manage your finances with ease
          </p>
        </div>
        
        <button
          onClick={loadData}
          className="btn-outline flex items-center space-x-2"
          disabled={loading}
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="mb-6 flex items-center space-x-2 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
          <AlertCircle className="h-5 w-5 text-danger-500" />
          <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
        </div>
      )}

      {/* Analytics Section */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100 flex items-center space-x-2">
            <PieChart className="h-5 w-5 text-primary-500" />
            <span>Financial Analytics</span>
          </h2>
          
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setAnalyticsView('overview')}
              className={`px-3 py-1 text-sm rounded-lg transition-colors ${
                analyticsView === 'overview' 
                  ? 'bg-primary-500 text-white' 
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              Overview
            </button>
            <button
              onClick={() => setAnalyticsView('spending')}
              className={`px-3 py-1 text-sm rounded-lg transition-colors ${
                analyticsView === 'spending' 
                  ? 'bg-primary-500 text-white' 
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              Spending
            </button>
            <button
              onClick={() => setAnalyticsView('trends')}
              className={`px-3 py-1 text-sm rounded-lg transition-colors ${
                analyticsView === 'trends' 
                  ? 'bg-primary-500 text-white' 
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              Trends
            </button>
          </div>
        </div>

        {/* Analytics Content */}
        {analyticsView === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            {/* Budget vs Spending Chart */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center space-x-2">
                <BarChart3 className="h-5 w-5 text-secondary-500" />
                <span>Budget vs Spending</span>
              </h3>
              {getBudgetVsSpendingData().length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={getBudgetVsSpendingData()}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip formatter={(value) => `₹${value.toLocaleString('en-IN')}`} />
                    <Legend />
                    <Bar dataKey="budget" fill="#10B981" name="Budget" />
                    <Bar dataKey="spent" fill="#EF4444" name="Spent" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  <div className="text-center">
                    <BarChart3 className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No spending data available</p>
                  </div>
                </div>
              )}
            </div>

            {/* Category Distribution Pie Chart */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center space-x-2">
                <PieChart className="h-5 w-5 text-primary-500" />
                <span>Category Distribution</span>
              </h3>
              {categories.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <RechartsPieChart>
                    <Pie
                      data={categories.map((cat, index) => ({
                        name: cat.name,
                        value: cat.current_balance || 0,
                        color: cat.color || CHART_COLORS[index % CHART_COLORS.length]
                      }))}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {categories.map((cat, index) => (
                        <Cell key={`cell-${index}`} fill={cat.color || CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value) => `₹${value.toLocaleString('en-IN')}`} />
                  </RechartsPieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  <div className="text-center">
                    <PieChart className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No categories available</p>
                    <button
                      onClick={createDefaultCategories}
                      className="btn-primary mt-3"
                      disabled={loading || !user?.salary}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Create Default Categories
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {analyticsView === 'spending' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            {/* Spending by Category Pie Chart */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Spending by Category
              </h3>
              {getSpendingData().length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <RechartsPieChart>
                    <Pie
                      data={getSpendingData()}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="amount"
                      label={({ name, percentage }) => `${name} ${percentage}%`}
                    >
                      {getSpendingData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value) => `₹${value.toLocaleString('en-IN')}`} />
                  </RechartsPieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  <div className="text-center">
                    <PieChart className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No spending data available</p>
                  </div>
                </div>
              )}
            </div>

            {/* Spending Summary */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Spending Summary
              </h3>
              <div className="space-y-4">
                {getSpendingData().map((item, index) => (
                  <div key={item.name} className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div 
                        className="w-4 h-4 rounded-full"
                        style={{ backgroundColor: CHART_COLORS[index % CHART_COLORS.length] }}
                      />
                      <span className="text-gray-900 dark:text-gray-100">{item.name}</span>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold text-gray-900 dark:text-gray-100">
                        ₹{item.amount.toLocaleString('en-IN')}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {item.percentage}%
                      </p>
                    </div>
                  </div>
                ))}
                {getSpendingData().length === 0 && (
                  <p className="text-center text-gray-500 dark:text-gray-400 py-8">
                    No spending data available
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {analyticsView === 'trends' && (
          <div className="card mb-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center space-x-2">
              <Calendar className="h-5 w-5 text-primary-500" />
              <span>Monthly Spending Trends</span>
            </h3>
            {getMonthlyTrends().length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={getMonthlyTrends()}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="month" />
                  <YAxis />
                  <Tooltip formatter={(value) => `₹${value.toLocaleString('en-IN')}`} />
                  <Legend />
                  <Line type="monotone" dataKey="amount" stroke="#3B82F6" name="Amount Spent" />
                  <Line type="monotone" dataKey="count" stroke="#10B981" name="Transactions" />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                <div className="text-center">
                  <Calendar className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>No trend data available</p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Enhanced Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Total Salary */}
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Monthly Salary</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                ₹{user?.salary?.toLocaleString('en-IN') || '0'}
              </p>
            </div>
            <Wallet className="h-8 w-8 text-primary-500" />
          </div>
        </div>

        {/* Available Balance */}
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center space-x-2">
                <p className="text-sm text-gray-600 dark:text-gray-400">Available Balance</p>
                <button
                  onClick={() => setShowBalances(!showBalances)}
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                >
                  {showBalances ? (
                    <Eye className="h-4 w-4 text-gray-400" />
                  ) : (
                    <EyeOff className="h-4 w-4 text-gray-400" />
                  )}
                </button>
              </div>
              <p className="text-2xl font-bold text-secondary-600 dark:text-secondary-400">
                {showBalances ? `₹${totalBalance.toLocaleString('en-IN')}` : '••••••'}
              </p>
            </div>
            <TrendingUp className="h-8 w-8 text-secondary-500" />
          </div>
        </div>

        {/* Total Spent */}
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Spent</p>
              <p className="text-2xl font-bold text-danger-600 dark:text-danger-400">
                {showBalances ? `₹${totalSpent.toLocaleString('en-IN')}` : '••••••'}
              </p>
            </div>
            <Target className="h-8 w-8 text-danger-500" />
          </div>
        </div>

        {/* Active Categories */}
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Active Categories</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {categories.length}
              </p>
            </div>
            <div className="h-8 w-8 bg-primary-100 dark:bg-primary-900/20 rounded-full flex items-center justify-center">
              <span className="text-primary-600 dark:text-primary-400 font-semibold">
                {categories.length}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Payment Section */}
      <div className="card mb-8">
        <div className="flex items-center space-x-2 mb-4">
          <Send className="h-5 w-5 text-primary-500" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Quick Payment
          </h2>
        </div>

        <form onSubmit={handlePayment} className="space-y-4">
          {paymentError && (
            <div className="flex items-center space-x-2 p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
              <AlertCircle className="h-5 w-5 text-danger-500" />
              <p className="text-sm text-danger-700 dark:text-danger-400">{paymentError}</p>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Amount (₹)
              </label>
              <input
                type="number"
                name="amount"
                value={paymentForm.amount}
                onChange={handlePaymentFormChange}
                className="input w-full"
                placeholder="Enter amount"
                min="1"
                step="0.01"
                disabled={paymentLoading}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Category
              </label>
              <select
                name="category_id"
                value={paymentForm.category_id}
                onChange={handlePaymentFormChange}
                className="input w-full"
                disabled={paymentLoading}
              >
                <option value="">Select category</option>
                {categories.map(category => (
                  <option key={category.id} value={category.id}>
                    {category.name} (₹{category.current_balance?.toLocaleString('en-IN') || '0'})
                  </option>
                ))}
              </select>
              {selectedCategory && (
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Available: ₹{selectedCategory.current_balance?.toLocaleString('en-IN') || '0'}
                </p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Merchant UPI ID
              </label>
              <div className="flex space-x-2">
                <input
                  type="text"
                  name="merchant_upi"
                  value={paymentForm.merchant_upi}
                  onChange={handlePaymentFormChange}
                  className="input flex-1"
                  placeholder="merchant@upi"
                  disabled={paymentLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowQRScanner(true)}
                  className="btn-outline px-3"
                  disabled={paymentLoading}
                >
                  <QrCode className="h-4 w-4" />
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Merchant Name
              </label>
              <input
                type="text"
                name="merchant_name"
                value={paymentForm.merchant_name}
                onChange={handlePaymentFormChange}
                className="input w-full"
                placeholder="Merchant name (optional)"
                disabled={paymentLoading}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Note (Optional)
            </label>
            <input
              type="text"
              name="note"
              value={paymentForm.note}
              onChange={handlePaymentFormChange}
              className="input w-full"
              placeholder="Payment note"
              disabled={paymentLoading}
            />
          </div>

          <button
            type="submit"
            disabled={paymentLoading || !paymentForm.amount || !paymentForm.category_id || !paymentForm.merchant_upi}
            className="btn-primary w-full md:w-auto flex items-center justify-center space-x-2"
          >
            {paymentLoading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                <span>Processing...</span>
              </>
            ) : (
              <>
                <Send className="h-4 w-4" />
                <span>Pay Now</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Categories Grid */}
      {categories.length > 0 && (
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Your Categories
            </h2>
            <button
              onClick={createDefaultCategories}
              className="btn-outline text-sm"
              disabled={loading || categories.length >= 7}
            >
              <Plus className="h-4 w-4 mr-1" />
              Add Default Categories
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {categories.map(category => {
              const defaultCat = defaultCategories.find(dc => dc.name === category.name)
              const spentAmount = transactions
                .filter(t => t.status === 'success' && t.category_name === category.name)
                .reduce((sum, t) => sum + t.amount, 0)
              const totalBudget = category.current_balance + spentAmount
              const spentPercentage = totalBudget > 0 ? (spentAmount / totalBudget) * 100 : 0
              
              return (
                <div key={category.id} className="card hover:shadow-md transition-shadow">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{defaultCat?.icon || '📊'}</span>
                      <h3 className="font-medium text-gray-900 dark:text-gray-100 text-sm">
                        {category.name}
                      </h3>
                    </div>
                    <div 
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: category.color }}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-500 dark:text-gray-400">Available</span>
                      <span className="font-semibold text-gray-900 dark:text-gray-100">
                        {showBalances ? `₹${(category.current_balance || 0).toLocaleString('en-IN')}` : '••••••'}
                      </span>
                    </div>
                    
                    {spentAmount > 0 && (
                      <>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-500 dark:text-gray-400">Spent</span>
                          <span className="text-sm text-danger-600 dark:text-danger-400">
                            ₹{spentAmount.toLocaleString('en-IN')}
                          </span>
                        </div>
                        
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div 
                            className="bg-gradient-to-r from-secondary-500 to-danger-500 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${Math.min(spentPercentage, 100)}%` }}
                          />
                        </div>
                        
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            {spentPercentage.toFixed(1)}% used
                          </span>
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            {category.percentage > 0 
                              ? `${category.percentage}% of salary`
                              : `₹${category.fixed_amount || 0} fixed`
                            }
                          </span>
                        </div>
                      </>
                    )}
                    
                    {spentAmount === 0 && (
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {category.percentage > 0 
                          ? `${category.percentage}% of salary`
                          : `₹${category.fixed_amount || 0} fixed`
                        }
                      </p>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Recent Transactions */}
      {transactions.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Recent Transactions
          </h2>
          <div className="card">
            <div className="space-y-3">
              {transactions.slice(0, 5).map(transaction => (
                <div key={transaction.id} className="flex items-center justify-between py-2 border-b border-gray-100 dark:border-gray-700 last:border-0">
                  <div className="flex items-center space-x-3">
                    <div 
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: transaction.category_color }}
                    />
                    <div>
                      <p className="font-medium text-gray-900 dark:text-gray-100">
                        {transaction.merchant_name || 'Unknown Merchant'}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {transaction.category_name} • {new Date(transaction.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="font-medium text-gray-900 dark:text-gray-100">
                      -₹{transaction.amount.toLocaleString('en-IN')}
                    </p>
                    <p className={`text-xs ${
                      transaction.status === 'success' ? 'text-secondary-600' :
                      transaction.status === 'failed' ? 'text-danger-600' :
                      'text-yellow-600'
                    }`}>
                      {transaction.status}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Empty States */}
      {categories.length === 0 && (
        <div className="card text-center py-12">
          <Wallet className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
            No categories yet
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Create categories to start organizing your finances
          </p>
          
          <div className="flex flex-col sm:flex-row items-center justify-center space-y-3 sm:space-y-0 sm:space-x-3">
            <button 
              onClick={createDefaultCategories}
              className="btn-primary"
              disabled={loading || !user?.salary}
            >
              <Target className="h-4 w-4 mr-2" />
              Create Default Budget Plan
            </button>
            <span className="text-gray-400">or</span>
            <button className="btn-outline">
              <Plus className="h-4 w-4 mr-2" />
              Create Custom Category
            </button>
          </div>
          
          {!user?.salary && (
            <p className="text-sm text-yellow-600 dark:text-yellow-400 mt-4">
              💡 Set your salary in Profile first to create budget categories
            </p>
          )}
          
          {/* Default Categories Preview */}
          <div className="mt-8 text-left">
            <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">
              Default Budget Plan Includes:
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
              {defaultCategories.map((cat, index) => (
                <div key={index} className="flex items-center space-x-2 text-gray-600 dark:text-gray-400">
                  <span>{cat.icon}</span>
                  <span>{cat.name}</span>
                  <span className="text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                    {cat.percentage}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

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
    </div>
  )
}

export default Dashboard