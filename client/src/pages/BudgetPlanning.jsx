import React, { useState } from 'react'
import { 
  Plus, 
  Target, 
  PieChart, 
  Calculator, 
  Edit3, 
  Trash2,
  RefreshCw,
  AlertCircle,
  CheckCircle
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useBalance } from '../contexts/BalanceContext'
import Toast from '../components/Toast'
import api from '../services/api'

function BudgetPlanning() {
  const { user } = useAuth()
  const { 
    categories, 
    loading, 
    error, 
    totalBalance, 
    totalBudget,
    loadData,
    setError
  } = useBalance()
  
  const [toast, setToast] = useState(null)
  const [showAddCategory, setShowAddCategory] = useState(false)
  const [editingCategory, setEditingCategory] = useState(null)
  
  // Form state
  const [categoryForm, setCategoryForm] = useState({
    name: '',
    percentage: '',
    fixed_amount: '',
    color: '#3B82F6',
    allocation_type: 'percentage' // 'percentage' or 'fixed'
  })

  // Default categories for quick setup
  const defaultCategories = [
    { name: 'Dining & Restaurants', percentage: 25, color: '#EF4444', icon: '🍽️' },
    { name: 'Transportation', percentage: 15, color: '#3B82F6', icon: '🚗' },
    { name: 'Entertainment', percentage: 10, color: '#8B5CF6', icon: '🎬' },
    { name: 'Shopping', percentage: 15, color: '#F59E0B', icon: '🛍️' },
    { name: 'Bills & Utilities', percentage: 20, color: '#10B981', icon: '💡' },
    { name: 'Healthcare', percentage: 5, color: '#EC4899', icon: '🏥' },
    { name: 'Savings', percentage: 10, color: '#6B7280', icon: '💰' }
  ]

  const showToast = (message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  const handleFormChange = (e) => {
    const { name, value } = e.target
    setCategoryForm(prev => ({
      ...prev,
      [name]: value
    }))
  }

  const resetForm = () => {
    setCategoryForm({
      name: '',
      percentage: '',
      fixed_amount: '',
      color: '#3B82F6',
      allocation_type: 'percentage'
    })
    setShowAddCategory(false)
    setEditingCategory(null)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!user?.salary && categoryForm.allocation_type === 'percentage') {
      setError('Please set your salary in Profile first to use percentage-based categories')
      return
    }

    try {
      const categoryData = {
        name: categoryForm.name,
        color: categoryForm.color,
        ...(categoryForm.allocation_type === 'percentage' 
          ? { percentage: parseFloat(categoryForm.percentage) }
          : { fixed_amount: parseFloat(categoryForm.fixed_amount) }
        )
      }

      if (editingCategory) {
        await api.put(`/categories/${editingCategory.id}`, categoryData)
        showToast('Category updated successfully!')
      } else {
        await api.post('/categories', categoryData)
        showToast('Category created successfully!')
      }
      
      await loadData()
      resetForm()
    } catch (err) {
      console.error('❌ Failed to save category:', err)
      setError(err.response?.data?.message || 'Failed to save category')
    }
  }

  const handleEdit = (category) => {
    setCategoryForm({
      name: category.name,
      percentage: category.percentage || '',
      fixed_amount: category.fixed_amount || '',
      color: category.color || '#3B82F6',
      allocation_type: category.percentage > 0 ? 'percentage' : 'fixed'
    })
    setEditingCategory(category)
    setShowAddCategory(true)
  }

  const handleDelete = async (categoryId) => {
    if (!confirm('Are you sure you want to delete this category?')) return

    try {
      await api.delete(`/categories/${categoryId}`)
      await loadData()
      showToast('Category deleted successfully!')
    } catch (err) {
      console.error('❌ Failed to delete category:', err)
      setError(err.response?.data?.message || 'Failed to delete category')
    }
  }

  const createDefaultCategories = async () => {
    if (!user?.salary) {
      setError('Please set your salary in Profile first')
      return
    }

    try {
      // Get existing category names to avoid duplicates
      const existingNames = categories.map(cat => cat.name.toLowerCase())
      
      // Filter out categories that already exist
      const newCategories = defaultCategories.filter(cat => 
        !existingNames.includes(cat.name.toLowerCase())
      )
      
      if (newCategories.length === 0) {
        showToast('All default categories already exist!', 'warning')
        return
      }

      await api.post('/categories/bulk', {
        categories: newCategories
      })
      
      await api.post('/categories/recalculate')
      await loadData()
      showToast(`${newCategories.length} new categories created successfully!`)
    } catch (err) {
      console.error('❌ Failed to create default categories:', err)
      setError(err.response?.data?.message || 'Failed to create default categories')
    }
  }

  const recalculateBalances = async () => {
    try {
      await api.post('/categories/recalculate')
      await loadData()
      showToast('Balances recalculated successfully!')
    } catch (err) {
      console.error('❌ Failed to recalculate:', err)
      setError(err.response?.data?.message || 'Failed to recalculate balances')
    }
  }

  // Calculate totals
  const totalPercentage = categories
    .filter(cat => cat.percentage > 0)
    .reduce((sum, cat) => sum + cat.percentage, 0)
  
  const totalFixedAmount = categories
    .filter(cat => cat.fixed_amount > 0)
    .reduce((sum, cat) => sum + cat.fixed_amount, 0)

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">
            Budget Planning 🎯
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Organize your spending into categories and manage your budget
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button
            onClick={createDefaultCategories}
            className="btn-secondary flex items-center space-x-2"
            disabled={loading || !user?.salary}
          >
            <Target className="h-4 w-4" />
            <span>Create Default Budget Plan</span>
          </button>
          
          <button
            onClick={recalculateBalances}
            className="btn-outline flex items-center space-x-2"
            disabled={loading}
          >
            <Calculator className="h-4 w-4" />
            <span>Recalculate</span>
          </button>
          
          <button
            onClick={loadData}
            className="btn-outline flex items-center space-x-2"
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          
          <button
            onClick={() => setShowAddCategory(true)}
            className="btn-primary flex items-center space-x-2"
          >
            <Plus className="h-4 w-4" />
            <span>Add Category</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 flex items-center space-x-2 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
          <AlertCircle className="h-5 w-5 text-danger-500" />
          <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
        </div>
      )}

      {/* Budget Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="card">
          <div className="flex items-center space-x-3">
            <Target className="h-8 w-8 text-primary-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Categories</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {categories.length}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <PieChart className="h-8 w-8 text-secondary-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Percentage</p>
              <p className={`text-2xl font-bold ${
                totalPercentage > 100 ? 'text-danger-600' : 
                totalPercentage === 100 ? 'text-secondary-600' : 'text-gray-900 dark:text-gray-100'
              }`}>
                {totalPercentage}%
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <Calculator className="h-8 w-8 text-accent-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Fixed Amount</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                ₹{totalFixedAmount.toLocaleString('en-IN')}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <CheckCircle className="h-8 w-8 text-purple-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Available Balance</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                ₹{totalBalance.toLocaleString('en-IN')}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Categories List */}
      {categories.length > 0 ? (
        <div className="card mb-8">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
              Your Budget Categories
            </h2>
            {totalPercentage !== 100 && categories.some(cat => cat.percentage > 0) && (
              <div className="text-sm text-yellow-600 dark:text-yellow-400">
                ⚠️ Percentage total: {totalPercentage}% (should be 100%)
              </div>
            )}
          </div>
          
          <div className="space-y-4">
            {categories.map(category => {
              const defaultCat = defaultCategories.find(dc => dc.name === category.name)
              
              return (
                <div key={category.id} className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-xl hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                  <div className="flex items-center space-x-4">
                    <div 
                      className="w-4 h-4 rounded-full"
                      style={{ backgroundColor: category.color }}
                    />
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{defaultCat?.icon || '📊'}</span>
                      <div>
                        <h3 className="font-medium text-gray-900 dark:text-gray-100">
                          {category.name}
                        </h3>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {category.percentage > 0 
                            ? `${category.percentage}% of salary`
                            : `₹${category.fixed_amount || 0} fixed amount`
                          }
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <p className="font-semibold text-gray-900 dark:text-gray-100">
                        ₹{(category.current_balance || 0).toLocaleString('en-IN')}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        Available
                      </p>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleEdit(category)}
                        className="p-2 text-gray-400 hover:text-primary-500 transition-colors"
                      >
                        <Edit3 className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(category.id)}
                        className="p-2 text-gray-400 hover:text-danger-500 transition-colors"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ) : (
        <div className="card text-center py-12 mb-8">
          <Target className="h-16 w-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-xl font-medium text-gray-900 dark:text-gray-100 mb-2">
            No budget categories yet
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Create categories to organize your spending and track your budget
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
            <button 
              onClick={() => setShowAddCategory(true)}
              className="btn-outline"
            >
              <Plus className="h-4 w-4 mr-2" />
              Create Custom Category
            </button>
          </div>
          
          {!user?.salary && (
            <p className="text-sm text-yellow-600 dark:text-yellow-400 mt-4">
              💡 Set your salary in Profile first to create percentage-based categories
            </p>
          )}
        </div>
      )}

      {/* Default Categories Preview */}
      <div className="card mb-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
              🎯 Default Budget Plan
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Quick start with our recommended budget allocation based on financial best practices
            </p>
          </div>
          <button 
            onClick={createDefaultCategories}
            className="btn-primary"
            disabled={loading || !user?.salary}
          >
            <Target className="h-4 w-4 mr-2" />
            Create Default Plan
          </button>
        </div>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mb-6">
          {defaultCategories.map((cat, index) => (
            <div key={index} className="flex items-center space-x-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
              <span className="text-2xl">{cat.icon}</span>
              <div className="flex-1">
                <p className="font-medium text-gray-900 dark:text-gray-100 text-sm">
                  {cat.name}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {cat.percentage}% • ₹{user?.salary ? Math.round((user.salary * cat.percentage) / 100).toLocaleString('en-IN') : '0'}
                </p>
              </div>
              <div 
                className="w-4 h-4 rounded-full shadow-sm"
                style={{ backgroundColor: cat.color }}
              />
            </div>
          ))}
        </div>
        
        <div className="bg-primary-50 dark:bg-primary-900/20 p-4 rounded-xl">
          <div className="flex items-start space-x-3">
            <CheckCircle className="h-5 w-5 text-primary-600 dark:text-primary-400 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-primary-900 dark:text-primary-100 mb-1">
                Why use the default plan?
              </p>
              <p className="text-xs text-primary-700 dark:text-primary-300">
                Based on the 50/30/20 rule and financial expert recommendations. You can always customize categories later to match your lifestyle.
              </p>
            </div>
          </div>
        </div>
        
        {!user?.salary && (
          <div className="mt-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-xl">
            <div className="flex items-center space-x-2">
              <AlertCircle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
              <p className="text-sm text-yellow-800 dark:text-yellow-200">
                💡 Set your salary in Profile Settings first to see calculated amounts for each category
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Add/Edit Category Modal */}
      {showAddCategory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 w-full max-w-md mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              {editingCategory ? 'Edit Category' : 'Add New Category'}
            </h3>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Category Name
                </label>
                <input
                  type="text"
                  name="name"
                  value={categoryForm.name}
                  onChange={handleFormChange}
                  className="input w-full"
                  placeholder="e.g., Food & Dining"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Allocation Type
                </label>
                <select
                  name="allocation_type"
                  value={categoryForm.allocation_type}
                  onChange={handleFormChange}
                  className="input w-full"
                >
                  <option value="percentage">Percentage of Salary</option>
                  <option value="fixed">Fixed Amount</option>
                </select>
              </div>

              {categoryForm.allocation_type === 'percentage' ? (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Percentage (%)
                  </label>
                  <input
                    type="number"
                    name="percentage"
                    value={categoryForm.percentage}
                    onChange={handleFormChange}
                    className="input w-full"
                    placeholder="25"
                    min="0"
                    max="100"
                    step="0.1"
                    required
                  />
                </div>
              ) : (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Fixed Amount (₹)
                  </label>
                  <input
                    type="number"
                    name="fixed_amount"
                    value={categoryForm.fixed_amount}
                    onChange={handleFormChange}
                    className="input w-full"
                    placeholder="5000"
                    min="0"
                    step="1"
                    required
                  />
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Color
                </label>
                <input
                  type="color"
                  name="color"
                  value={categoryForm.color}
                  onChange={handleFormChange}
                  className="w-full h-10 rounded-lg border border-gray-300 dark:border-gray-600"
                />
              </div>

              <div className="flex items-center space-x-3 pt-4">
                <button
                  type="submit"
                  className="btn-primary flex-1"
                >
                  {editingCategory ? 'Update Category' : 'Create Category'}
                </button>
                <button
                  type="button"
                  onClick={resetForm}
                  className="btn-outline flex-1"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

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

export default BudgetPlanning