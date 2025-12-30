import React, { useState } from 'react'
import { 
  PieChart, 
  BarChart3, 
  Calendar, 
  TrendingUp,
  Target,
  DollarSign
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
import { useBalance } from '../contexts/BalanceContext'

function Analytics() {
  const { categories, transactions, totalBalance, totalSpent, totalBudget } = useBalance()
  const [analyticsView, setAnalyticsView] = useState('overview')

  const CHART_COLORS = ['#EF4444', '#3B82F6', '#8B5CF6', '#F59E0B', '#10B981', '#EC4899', '#6B7280', '#14B8A6', '#F97316', '#84CC16']

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

  const spendingData = getSpendingData()
  const budgetVsSpendingData = getBudgetVsSpendingData()
  const monthlyTrends = getMonthlyTrends()

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Financial Analytics 📊
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Insights into your spending patterns and budget performance
        </p>
      </div>

      {/* Analytics Navigation */}
      <div className="flex items-center space-x-2 mb-8">
        <button
          onClick={() => setAnalyticsView('overview')}
          className={`px-4 py-2 text-sm rounded-xl transition-colors ${
            analyticsView === 'overview' 
              ? 'bg-primary-500 text-white' 
              : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => setAnalyticsView('spending')}
          className={`px-4 py-2 text-sm rounded-xl transition-colors ${
            analyticsView === 'spending' 
              ? 'bg-primary-500 text-white' 
              : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
          }`}
        >
          Spending
        </button>
        <button
          onClick={() => setAnalyticsView('trends')}
          className={`px-4 py-2 text-sm rounded-xl transition-colors ${
            analyticsView === 'trends' 
              ? 'bg-primary-500 text-white' 
              : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
          }`}
        >
          Trends
        </button>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-primary-100 dark:bg-primary-900/20 rounded-xl">
              <DollarSign className="h-6 w-6 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Savings Rate</p>
              <p className="text-xl font-bold text-gray-900 dark:text-gray-100">
                {totalBudget > 0 ? ((totalBalance / totalBudget) * 100).toFixed(1) : 0}%
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-secondary-100 dark:bg-secondary-900/20 rounded-xl">
              <Target className="h-6 w-6 text-secondary-600 dark:text-secondary-400" />
            </div>
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Budget Used</p>
              <p className="text-xl font-bold text-gray-900 dark:text-gray-100">
                {totalBudget > 0 ? ((totalSpent / totalBudget) * 100).toFixed(1) : 0}%
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-accent-100 dark:bg-accent-900/20 rounded-xl">
              <TrendingUp className="h-6 w-6 text-accent-600 dark:text-accent-400" />
            </div>
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Avg. Transaction</p>
              <p className="text-xl font-bold text-gray-900 dark:text-gray-100">
                ₹{transactions.length > 0 ? Math.round(totalSpent / transactions.length).toLocaleString('en-IN') : '0'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Analytics Content */}
      {analyticsView === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Budget vs Spending Chart */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center space-x-2">
              <BarChart3 className="h-5 w-5 text-secondary-500" />
              <span>Budget vs Spending</span>
            </h3>
            {budgetVsSpendingData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={budgetVsSpendingData}>
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

          {/* Category Distribution */}
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
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {analyticsView === 'spending' && (
        <div className="space-y-8">
          {/* Overall Spending Chart */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Spending by Category */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Overall Spending Distribution
              </h3>
              {spendingData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <RechartsPieChart>
                    <Pie
                      data={spendingData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="amount"
                      label={({ name, percentage }) => `${name} ${percentage}%`}
                    >
                      {spendingData.map((entry, index) => (
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
                {spendingData.map((item, index) => (
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
                {spendingData.length === 0 && (
                  <p className="text-center text-gray-500 dark:text-gray-400 py-8">
                    No spending data available
                  </p>
                )}
              </div>
            </div>
          </div>

          {/* Individual Category Breakdown */}
          <div>
            <h3 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-6">
              Category-wise Budget Analysis
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {categories.map((category, index) => {
                const spentAmount = transactions
                  .filter(t => t.status === 'success' && t.category_name === category.name)
                  .reduce((sum, t) => sum + t.amount, 0)
                
                const totalBudget = category.current_balance + spentAmount
                const spentPercentage = totalBudget > 0 ? (spentAmount / totalBudget) * 100 : 0
                const remainingPercentage = 100 - spentPercentage
                
                const categoryData = [
                  { name: 'Spent', value: spentAmount, color: '#EF4444' },
                  { name: 'Remaining', value: category.current_balance, color: category.color || '#10B981' }
                ]

                return (
                  <div key={category.id} className="card">
                    <div className="flex items-center space-x-3 mb-4">
                      <div 
                        className="w-4 h-4 rounded-full"
                        style={{ backgroundColor: category.color || '#6B7280' }}
                      />
                      <h4 className="font-semibold text-gray-900 dark:text-gray-100">
                        {category.name}
                      </h4>
                    </div>
                    
                    {totalBudget > 0 ? (
                      <>
                        <ResponsiveContainer width="100%" height={200}>
                          <RechartsPieChart>
                            <Pie
                              data={categoryData}
                              cx="50%"
                              cy="50%"
                              innerRadius={40}
                              outerRadius={80}
                              dataKey="value"
                              startAngle={90}
                              endAngle={450}
                            >
                              {categoryData.map((entry, idx) => (
                                <Cell key={`cell-${idx}`} fill={entry.color} />
                              ))}
                            </Pie>
                            <Tooltip formatter={(value) => `₹${value.toLocaleString('en-IN')}`} />
                          </RechartsPieChart>
                        </ResponsiveContainer>
                        
                        <div className="space-y-2 mt-4">
                          <div className="flex justify-between items-center">
                            <span className="text-sm text-gray-600 dark:text-gray-400">Budget</span>
                            <span className="font-medium text-gray-900 dark:text-gray-100">
                              ₹{totalBudget.toLocaleString('en-IN')}
                            </span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-sm text-gray-600 dark:text-gray-400">Spent</span>
                            <span className="font-medium text-danger-600 dark:text-danger-400">
                              ₹{spentAmount.toLocaleString('en-IN')} ({spentPercentage.toFixed(1)}%)
                            </span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-sm text-gray-600 dark:text-gray-400">Remaining</span>
                            <span className="font-medium text-secondary-600 dark:text-secondary-400">
                              ₹{category.current_balance.toLocaleString('en-IN')} ({remainingPercentage.toFixed(1)}%)
                            </span>
                          </div>
                          
                          {/* Progress bar */}
                          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-3">
                            <div 
                              className="bg-gradient-to-r from-danger-500 to-danger-600 h-2 rounded-full transition-all duration-300"
                              style={{ width: `${Math.min(spentPercentage, 100)}%` }}
                            />
                          </div>
                          
                          {spentPercentage > 80 && (
                            <p className="text-xs text-danger-600 dark:text-danger-400 mt-2">
                              ⚠️ High spending alert
                            </p>
                          )}
                        </div>
                      </>
                    ) : (
                      <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                        <Target className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p className="text-sm">No budget allocated</p>
                      </div>
                    )}
                  </div>
                )
              })}
              
              {categories.length === 0 && (
                <div className="col-span-full text-center py-12 text-gray-500 dark:text-gray-400">
                  <PieChart className="h-16 w-16 mx-auto mb-4 opacity-50" />
                  <p className="text-lg mb-2">No categories found</p>
                  <p className="text-sm">Create budget categories to see detailed analytics</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {analyticsView === 'trends' && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center space-x-2">
            <Calendar className="h-5 w-5 text-primary-500" />
            <span>Monthly Spending Trends</span>
          </h3>
          {monthlyTrends.length > 0 ? (
            <ResponsiveContainer width="100%" height={400}>
              <LineChart data={monthlyTrends}>
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
  )
}

export default Analytics