import React, { useState, useEffect } from 'react'
import { 
  Receipt, 
  Filter, 
  RefreshCw, 
  AlertCircle,
  CheckCircle,
  XCircle,
  Clock,
  Search
} from 'lucide-react'
import api from '../services/api'

function Transactions() {
  const [transactions, setTransactions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    loadTransactions()
  }, [])

  const loadTransactions = async () => {
    try {
      setLoading(true)
      setError('')
      
      const response = await api.get('/transactions')
      setTransactions(response.data.transactions || [])
    } catch (err) {
      console.error('❌ Failed to load transactions:', err)
      setError(err.userMessage || 'Failed to load transactions')
    } finally {
      setLoading(false)
    }
  }

  const updateTransactionStatus = async (transactionId, status) => {
    try {
      await api.put(`/transactions/${transactionId}/status`, { status })
      await loadTransactions()
    } catch (err) {
      console.error('❌ Failed to update transaction:', err)
      setError(err.response?.data?.message || err.userMessage || 'Failed to update transaction')
    }
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="h-5 w-5 text-secondary-500" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-danger-500" />
      case 'cancelled':
        return <XCircle className="h-5 w-5 text-gray-500" />
      default:
        return <Clock className="h-5 w-5 text-yellow-500" />
    }
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'success':
        return 'text-secondary-600 bg-secondary-50 dark:bg-secondary-900/20'
      case 'failed':
        return 'text-danger-600 bg-danger-50 dark:bg-danger-900/20'
      case 'cancelled':
        return 'text-gray-600 bg-gray-50 dark:bg-gray-900/20'
      default:
        return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20'
    }
  }

  const filteredTransactions = transactions.filter(transaction => {
    const matchesFilter = filter === 'all' || transaction.status === filter
    const matchesSearch = !searchTerm || 
      transaction.merchant_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      transaction.category_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      transaction.note?.toLowerCase().includes(searchTerm.toLowerCase())
    
    return matchesFilter && matchesSearch
  })

  const getTransactionStats = () => {
    const stats = {
      total: transactions.length,
      success: transactions.filter(t => t.status === 'success').length,
      pending: transactions.filter(t => t.status === 'pending').length,
      failed: transactions.filter(t => t.status === 'failed').length + transactions.filter(t => t.status === 'cancelled').length,
      totalAmount: transactions
        .filter(t => t.status === 'success')
        .reduce((sum, t) => sum + t.amount, 0)
    }
    return stats
  }

  if (loading && transactions.length === 0) {
    return (
      <div className="p-6 flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </div>
    )
  }

  const stats = getTransactionStats()

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            Transactions
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            View and manage your payment history
          </p>
        </div>
        
        <button
          onClick={loadTransactions}
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

      {/* Stats */}
      {transactions.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Transactions</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                  {stats.total}
                </p>
              </div>
              <Receipt className="h-8 w-8 text-primary-500" />
            </div>
          </div>
          
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Successful</p>
                <p className="text-2xl font-bold text-secondary-600 dark:text-secondary-400">
                  {stats.success}
                </p>
              </div>
              <CheckCircle className="h-8 w-8 text-secondary-500" />
            </div>
          </div>
          
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Pending</p>
                <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                  {stats.pending}
                </p>
              </div>
              <Clock className="h-8 w-8 text-yellow-500" />
            </div>
          </div>
          
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Spent</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                  ₹{stats.totalAmount.toLocaleString('en-IN')}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters and Search */}
      {transactions.length > 0 && (
        <div className="card mb-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Filter className="h-4 w-4 text-gray-500" />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filter:</span>
              </div>
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="input w-auto"
              >
                <option value="all">All Status</option>
                <option value="success">Successful</option>
                <option value="pending">Pending</option>
                <option value="failed">Failed</option>
                <option value="cancelled">Cancelled</option>
              </select>
            </div>
            
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search transactions..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-10 w-full md:w-64"
              />
            </div>
          </div>
        </div>
      )}

      {/* Transactions List */}
      {filteredTransactions.length > 0 ? (
        <div className="card">
          <div className="space-y-4">
            {filteredTransactions.map(transaction => (
              <div key={transaction.id} className="flex items-center justify-between p-4 border border-gray-100 dark:border-gray-700 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div 
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: transaction.category_color }}
                  />
                  
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <h3 className="font-medium text-gray-900 dark:text-gray-100">
                        {transaction.merchant_name || 'Unknown Merchant'}
                      </h3>
                      {getStatusIcon(transaction.status)}
                    </div>
                    
                    <div className="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                      <span>{transaction.category_name}</span>
                      <span>•</span>
                      <span>{new Date(transaction.created_at).toLocaleString()}</span>
                      {transaction.note && (
                        <>
                          <span>•</span>
                          <span>{transaction.note}</span>
                        </>
                      )}
                    </div>
                    
                    {transaction.merchant_upi && (
                      <p className="text-xs text-gray-400 mt-1">
                        {transaction.merchant_upi}
                      </p>
                    )}
                  </div>
                </div>
                
                <div className="text-right">
                  <p className="font-semibold text-gray-900 dark:text-gray-100 mb-1">
                    ₹{transaction.amount.toLocaleString('en-IN')}
                  </p>
                  
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(transaction.status)}`}>
                      {transaction.status}
                    </span>
                    
                    {transaction.status === 'pending' && (
                      <div className="flex space-x-1">
                        <button
                          onClick={() => updateTransactionStatus(transaction.id, 'success')}
                          className="text-xs px-2 py-1 bg-secondary-100 text-secondary-700 rounded hover:bg-secondary-200"
                          title="Mark as successful"
                        >
                          ✓
                        </button>
                        <button
                          onClick={() => updateTransactionStatus(transaction.id, 'failed')}
                          className="text-xs px-2 py-1 bg-danger-100 text-danger-700 rounded hover:bg-danger-200"
                          title="Mark as failed"
                        >
                          ✗
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : transactions.length > 0 ? (
        <div className="card text-center py-12">
          <Search className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
            No transactions found
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Try adjusting your filters or search terms
          </p>
        </div>
      ) : (
        <div className="card text-center py-12">
          <Receipt className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
            No transactions yet
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Your payment history will appear here once you make transactions
          </p>
        </div>
      )}
    </div>
  )
}

export default Transactions