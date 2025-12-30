import React, { createContext, useContext, useState, useEffect } from 'react'
import api from '../services/api'
import { useAuth } from './AuthContext'

const BalanceContext = createContext()

export function useBalance() {
  const context = useContext(BalanceContext)
  if (!context) {
    throw new Error('useBalance must be used within a BalanceProvider')
  }
  return context
}

export function BalanceProvider({ children }) {
  const { user } = useAuth()
  const [categories, setCategories] = useState([])
  const [transactions, setTransactions] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Calculate totals
  const totalBalance = categories.reduce((sum, cat) => sum + (cat.current_balance || 0), 0)
  const totalSpent = transactions
    .filter(t => t.status === 'success')
    .reduce((sum, t) => sum + t.amount, 0)
  const totalBudget = user?.salary || 0

  // Load data from API
  const loadData = async () => {
    if (!user) return
    
    try {
      setLoading(true)
      setError('')
      
      const [categoriesRes, transactionsRes] = await Promise.all([
        api.get('/categories'),
        api.get('/transactions')
      ])
      
      setCategories(categoriesRes.data.categories || [])
      setTransactions(transactionsRes.data.transactions || [])
    } catch (err) {
      console.error('❌ Failed to load balance data:', err)
      setError(err.userMessage || 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }

  // Update category balance (optimistic update)
  const updateCategoryBalance = (categoryId, newBalance) => {
    setCategories(prev => 
      prev.map(cat => 
        cat.id === categoryId 
          ? { ...cat, current_balance: newBalance }
          : cat
      )
    )
  }

  // Add transaction (optimistic update)
  const addTransaction = (transaction) => {
    setTransactions(prev => [transaction, ...prev])
  }

  // Update transaction status
  const updateTransactionStatus = (transactionId, status) => {
    setTransactions(prev =>
      prev.map(t =>
        t.id === transactionId
          ? { ...t, status }
          : t
      )
    )
  }

  // Get category by ID
  const getCategoryById = (categoryId) => {
    return categories.find(cat => cat.id === categoryId)
  }

  // Get spending by category
  const getSpendingByCategory = (categoryId) => {
    return transactions
      .filter(t => t.category_id === categoryId && t.status === 'success')
      .reduce((sum, t) => sum + t.amount, 0)
  }

  // Validate payment amount
  const validatePayment = (categoryId, amount) => {
    const category = getCategoryById(categoryId)
    if (!category) {
      return { valid: false, error: 'Category not found' }
    }
    
    if (amount <= 0) {
      return { valid: false, error: 'Enter a valid amount' }
    }
    
    if (category.current_balance < amount) {
      return { 
        valid: false, 
        error: `Insufficient balance. Available: ₹${category.current_balance.toLocaleString('en-IN')}` 
      }
    }
    
    return { valid: true }
  }

  // Load data when user changes
  useEffect(() => {
    if (user) {
      loadData()
    } else {
      setCategories([])
      setTransactions([])
    }
  }, [user])

  const value = {
    // Data
    categories,
    transactions,
    loading,
    error,
    
    // Computed values
    totalBalance,
    totalSpent,
    totalBudget,
    
    // Actions
    loadData,
    updateCategoryBalance,
    addTransaction,
    updateTransactionStatus,
    getCategoryById,
    getSpendingByCategory,
    validatePayment,
    
    // Setters for direct updates
    setCategories,
    setTransactions,
    setError
  }

  return (
    <BalanceContext.Provider value={value}>
      {children}
    </BalanceContext.Provider>
  )
}