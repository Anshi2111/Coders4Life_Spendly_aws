import { useState } from 'react'
import { 
  Wallet, 
  TrendingUp, 
  Target, 
  PieChart,
  Plus,
  Send,
  RefreshCw
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { useBalance } from '../contexts/BalanceContext'
import QuickPayment from '../components/QuickPayment'

function Home() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { 
    categories, 
    transactions, 
    loading, 
    totalBalance, 
    totalSpent, 
    totalBudget,
    loadData
  } = useBalance()

  // UI state
  const [showQuickPayment, setShowQuickPayment] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState(null)

  // Default categories for fallback
  const defaultCategories = [
    { id: 'default-food', name: 'Food', balance: 5000, color: '#EF4444' },
    { id: 'default-rent', name: 'Rent', balance: 15000, color: '#3B82F6' },
    { id: 'default-travel', name: 'Travel', balance: 3000, color: '#8B5CF6' },
    { id: 'default-shopping', name: 'Shopping', balance: 7000, color: '#F59E0B' }
  ]

  // Get available categories (user categories + defaults if none exist)
  const availableCategories = categories?.length > 0 ? categories : defaultCategories

  const handleCategoryPayment = (category) => {
    setSelectedCategory(category)
    setShowQuickPayment(true)
  }

  const recentTransactions = transactions.slice(0, 3)
  const topCategories = categories
    .sort((a, b) => (b.current_balance || 0) - (a.current_balance || 0))
    .slice(0, 3)

  return (
    <div className="p-4 lg:p-6 max-w-7xl mx-auto overflow-x-hidden">
      {/* Welcome Header */}
      <div className="mb-6 lg:mb-8">
        <h1 className="text-2xl lg:text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2 break-words">
          Welcome back, {user?.name || 'User'}! 👋
        </h1>
        <p className="text-gray-600 dark:text-gray-400 text-sm lg:text-base">
          Here's your financial overview for today
        </p>
      </div>

      {/* Quick Stats - Mobile: 2x2 Grid, Desktop: 1x4 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 lg:gap-6 mb-6 lg:mb-8">
        {/* Total Balance */}
        <div className="card-brand p-3 lg:p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
            <div className="mb-2 lg:mb-0">
              <p className="text-white/80 text-xs lg:text-sm">Total Balance</p>
              <p className="text-lg lg:text-2xl font-bold text-white break-all">
                ₹{totalBalance.toLocaleString('en-IN')}
              </p>
            </div>
            <Wallet className="h-6 w-6 lg:h-8 lg:w-8 text-white/80 self-end lg:self-auto" />
          </div>
        </div>

        {/* Monthly Salary */}
        <div className="card p-3 lg:p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
            <div className="mb-2 lg:mb-0">
              <p className="text-xs lg:text-sm text-gray-600 dark:text-gray-400">Monthly Salary</p>
              <p className="text-lg lg:text-2xl font-bold text-gray-900 dark:text-gray-100 break-all">
                ₹{totalBudget.toLocaleString('en-IN')}
              </p>
            </div>
            <TrendingUp className="h-6 w-6 lg:h-8 lg:w-8 text-primary-500 self-end lg:self-auto" />
          </div>
        </div>

        {/* Total Spent */}
        <div className="card p-3 lg:p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
            <div className="mb-2 lg:mb-0">
              <p className="text-xs lg:text-sm text-gray-600 dark:text-gray-400">Total Spent</p>
              <p className="text-lg lg:text-2xl font-bold text-danger-600 dark:text-danger-400 break-all">
                ₹{totalSpent.toLocaleString('en-IN')}
              </p>
            </div>
            <Target className="h-6 w-6 lg:h-8 lg:w-8 text-danger-500 self-end lg:self-auto" />
          </div>
        </div>

        {/* Active Categories */}
        <div className="card p-3 lg:p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
            <div className="mb-2 lg:mb-0">
              <p className="text-xs lg:text-sm text-gray-600 dark:text-gray-400">Categories</p>
              <p className="text-lg lg:text-2xl font-bold text-gray-900 dark:text-gray-100">
                {categories.length}
              </p>
            </div>
            <PieChart className="h-6 w-6 lg:h-8 lg:w-8 text-secondary-500 self-end lg:self-auto" />
          </div>
        </div>
      </div>

      {/* Quick Payment Categories */}
      <div className="mb-6 lg:mb-8">
        <div className="flex items-center justify-between mb-4 lg:mb-6">
          <div className="flex items-center space-x-2">
            <Send className="h-4 w-4 lg:h-5 lg:w-5 text-primary-500" />
            <h2 className="text-lg lg:text-xl font-semibold text-gray-900 dark:text-gray-100">
              Quick Payment
            </h2>
          </div>
          <button 
            onClick={() => navigate('/budget-planning')}
            className="text-primary-500 hover:text-primary-600 text-xs lg:text-sm font-medium"
          >
            Manage Categories
          </button>
        </div>
        
        <p className="text-gray-600 dark:text-gray-400 mb-4 lg:mb-6 text-sm lg:text-base">
          Select a category to make instant UPI payments from your budget
        </p>

        {/* Categories Grid - Mobile: 1 column, Tablet: 2 columns, Desktop: 3-4 columns */}
        {availableCategories.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3 lg:gap-4">
            {availableCategories.map(category => {
              const balance = category.current_balance || category.balance || 0
              const isDefault = category.id?.toString().startsWith('default-')
              
              return (
                <div 
                  key={category.id}
                  onClick={() => handleCategoryPayment(category)}
                  className="card hover:shadow-lg transition-all duration-200 cursor-pointer group border-2 border-transparent hover:border-primary-200 dark:hover:border-primary-800 p-3 lg:p-4 min-h-[44px]"
                >
                  <div className="flex items-start justify-between mb-2 lg:mb-3">
                    <div 
                      className="w-3 h-3 lg:w-4 lg:h-4 rounded-full flex-shrink-0 mt-1"
                      style={{ backgroundColor: category.color || '#6B7280' }}
                    />
                    <div className="flex items-center space-x-1">
                      {category.hasQR && (
                        <div className="w-4 h-4 lg:w-5 lg:h-5 bg-secondary-100 dark:bg-secondary-900/20 rounded p-1">
                          <div className="w-full h-full bg-secondary-500 rounded-sm opacity-60" />
                        </div>
                      )}
                      <Send className="h-3 w-3 lg:h-4 lg:w-4 text-gray-400 group-hover:text-primary-500 transition-colors" />
                    </div>
                  </div>
                  
                  <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2 group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors text-sm lg:text-base break-words">
                    {category.name}
                  </h3>
                  
                  <div className="space-y-1 lg:space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs lg:text-sm text-gray-500 dark:text-gray-400">Available</span>
                      <span className="font-bold text-gray-900 dark:text-gray-100 text-xs lg:text-sm break-all">
                        ₹{balance.toLocaleString('en-IN')}
                      </span>
                    </div>
                    
                    {category.percentage > 0 && (
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        {category.percentage}% of salary
                      </div>
                    )}
                    
                    {category.savedUpiId && (
                      <div className="text-xs text-secondary-600 dark:text-secondary-400 truncate">
                        💳 {category.savedUpiId}
                      </div>
                    )}
                    
                    {isDefault && (
                      <div className="text-xs text-yellow-600 dark:text-yellow-400">
                        📋 Default category
                      </div>
                    )}
                  </div>
                  
                  <div className="mt-2 lg:mt-3 pt-2 lg:pt-3 border-t border-gray-100 dark:border-gray-700">
                    <div className="flex items-center justify-center text-xs lg:text-sm text-primary-600 dark:text-primary-400 group-hover:text-primary-700 dark:group-hover:text-primary-300 transition-colors min-h-[20px]">
                      <Wallet className="h-3 w-3 lg:h-4 lg:w-4 mr-1" />
                      Pay Now
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          <div className="card text-center py-8 lg:py-12">
            <Wallet className="h-12 w-12 lg:h-16 lg:w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg lg:text-xl font-medium text-gray-900 dark:text-gray-100 mb-2">
              No payment categories
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-6 text-sm lg:text-base">
              Create budget categories to start making payments
            </p>
            <button 
              onClick={() => navigate('/budget-planning')}
              className="btn-primary"
            >
              <Plus className="h-4 w-4 mr-2" />
              Create Categories
            </button>
          </div>
        )}
      </div>

      {/* Recent Activity - Mobile: Single column, Desktop: Two columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:gap-8">
        {/* Recent Transactions */}
        <div className="card p-4 lg:p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base lg:text-lg font-semibold text-gray-900 dark:text-gray-100">
              Recent Transactions
            </h2>
            <button 
              onClick={() => navigate('/transactions')}
              className="text-primary-500 hover:text-primary-600 text-xs lg:text-sm font-medium"
            >
              View All
            </button>
          </div>
          
          {recentTransactions.length > 0 ? (
            <div className="space-y-3">
              {recentTransactions.map(transaction => (
                <div key={transaction.id} className="flex items-center justify-between py-2">
                  <div className="flex items-center space-x-3 flex-1 min-w-0">
                    <div 
                      className="w-3 h-3 rounded-full flex-shrink-0"
                      style={{ backgroundColor: transaction.category_color || '#6B7280' }}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-gray-900 dark:text-gray-100 text-sm truncate">
                        {transaction.merchant_name || 'Unknown Merchant'}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                        {transaction.category_name} • {new Date(transaction.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0 ml-2">
                    <p className="font-medium text-gray-900 dark:text-gray-100 text-sm">
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
          ) : (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              <Target className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No transactions yet</p>
            </div>
          )}
        </div>

        {/* Top Categories */}
        <div className="card p-4 lg:p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base lg:text-lg font-semibold text-gray-900 dark:text-gray-100">
              Top Categories
            </h2>
            <button 
              onClick={() => navigate('/budget-planning')}
              className="text-primary-500 hover:text-primary-600 text-xs lg:text-sm font-medium"
            >
              View All
            </button>
          </div>
          
          {topCategories.length > 0 ? (
            <div className="space-y-4">
              {topCategories.map(category => (
                <div key={category.id} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3 flex-1 min-w-0">
                    <div 
                      className="w-4 h-4 rounded-full flex-shrink-0"
                      style={{ backgroundColor: category.color || '#6B7280' }}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-gray-900 dark:text-gray-100 text-sm truncate">
                        {category.name}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                        {category.percentage > 0 
                          ? `${category.percentage}% of salary`
                          : `₹${category.fixed_amount || 0} fixed`
                        }
                      </p>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0 ml-2">
                    <p className="font-semibold text-gray-900 dark:text-gray-100 text-sm">
                      ₹{(category.current_balance || 0).toLocaleString('en-IN')}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              <PieChart className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No categories yet</p>
            </div>
          )}
        </div>
      </div>

      {/* Quick Payment Modal */}
      <QuickPayment
        isOpen={showQuickPayment}
        onClose={() => {
          setShowQuickPayment(false)
          setSelectedCategory(null)
        }}
        preSelectedCategory={selectedCategory}
      />
    </div>
  )
}

export default Home