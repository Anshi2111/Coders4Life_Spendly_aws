import React, { useState, useEffect } from 'react'
import { 
  Plus, 
  Edit2, 
  Trash2, 
  Percent, 
  DollarSign, 
  AlertCircle,
  RefreshCw,
  Calculator
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import api from '../services/api'

function Categories() {
  const { user } = useAuth()
  const [categories, setCategories] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [editingCategory, setEditingCategory] = useState(null)
  
  const [formData, setFormData] = useState({
    name: '',
    percentage: '',
    fixed_amount: '',
    color: '#4F46E5'
  })
  const [formLoading, setFormLoading] = useState(false)
  const [formError, setFormError] = useState('')

  const colors = [
    '#4F46E5', '#7C3AED', '#DC2626', '#EA580C', 
    '#D97706', '#65A30D', '#059669', '#0891B2',
    '#0284C7', '#2563EB', '#7C2D12', '#BE185D'
  ]

  useEffect(() => {
    loadCategories()
  }, [])

  const loadCategories = async () => {
    try {
      setLoading(true)
      setError('')
      
      const response = await api.get('/categories')
      setCategories(response.data.categories || [])
    } catch (err) {
      console.error('❌ Failed to load categories:', err)
      setError(err.userMessage || 'Failed to load categories')
    } finally {
      setLoading(false)
    }
  }

  const handleFormChange = (e) => {
    const { name, value } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: value
    }))
    if (formError) setFormError('')
  }

  const validateForm = () => {
    if (!formData.name.trim()) {
      setFormError('Category name is required')
      return false
    }
    
    const percentage = parseFloat(formData.percentage) || 0
    const fixedAmount = parseFloat(formData.fixed_amount) || 0
    
    if (percentage === 0 && fixedAmount === 0) {
      setFormError('Please set either percentage or fixed amount')
      return false
    }
    
    if (percentage > 0 && fixedAmount > 0) {
      setFormError('Please set either percentage OR fixed amount, not both')
      return false
    }
    
    if (percentage > 100) {
      setFormError('Percentage cannot exceed 100%')
      return false
    }
    
    return true
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!validateForm()) {
      return
    }

    setFormLoading(true)
    setFormError('')

    try {
      const payload = {
        name: formData.name.trim(),
        percentage: parseFloat(formData.percentage) || 0,
        fixed_amount: parseFloat(formData.fixed_amount) || 0,
        color: formData.color
      }

      if (editingCategory) {
        await api.put(`/categories/${editingCategory.id}`, payload)
      } else {
        await api.post('/categories', payload)
      }
      
      await loadCategories()
      resetForm()
    } catch (err) {
      console.error('❌ Failed to save category:', err)
      setFormError(err.response?.data?.message || err.userMessage || 'Failed to save category')
    } finally {
      setFormLoading(false)
    }
  }

  const handleEdit = (category) => {
    setEditingCategory(category)
    setFormData({
      name: category.name,
      percentage: category.percentage || '',
      fixed_amount: category.fixed_amount || '',
      color: category.color || '#4F46E5'
    })
    setShowForm(true)
  }

  const handleDelete = async (category) => {
    if (!confirm(`Are you sure you want to delete "${category.name}"? This action cannot be undone.`)) {
      return
    }

    try {
      await api.delete(`/categories/${category.id}`)
      await loadCategories()
    } catch (err) {
      console.error('❌ Failed to delete category:', err)
      setError(err.response?.data?.message || err.userMessage || 'Failed to delete category')
    }
  }

  const resetForm = () => {
    setFormData({
      name: '',
      percentage: '',
      fixed_amount: '',
      color: '#4F46E5'
    })
    setEditingCategory(null)
    setShowForm(false)
    setFormError('')
  }

  const recalculateBalances = async () => {
    if (!user?.salary) {
      setError('Please set your salary in Profile first')
      return
    }

    try {
      setLoading(true)
      await api.post('/categories/recalculate')
      await loadCategories()
      setError('')
    } catch (err) {
      console.error('❌ Failed to recalculate balances:', err)
      setError(err.response?.data?.message || err.userMessage || 'Failed to recalculate balances')
    } finally {
      setLoading(false)
    }
  }

  const getTotalPercentage = () => {
    return categories.reduce((total, cat) => total + (cat.percentage || 0), 0)
  }

  const getTotalFixedAmount = () => {
    return categories.reduce((total, cat) => total + (cat.fixed_amount || 0), 0)
  }

  if (loading && categories.length === 0) {
    return (
      <div className="p-6 flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </div>
    )
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            Categories
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Organize your spending into categories
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button
            onClick={recalculateBalances}
            className="btn-outline flex items-center space-x-2"
            disabled={loading}
          >
            <Calculator className="h-4 w-4" />
            <span>Recalculate</span>
          </button>
          
          <button
            onClick={loadCategories}
            className="btn-outline flex items-center space-x-2"
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          
          <button
            onClick={() => setShowForm(true)}
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

      {/* Summary */}
      {categories.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Categories</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                  {categories.length}
                </p>
              </div>
            </div>
          </div>
          
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Percentage</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                  {getTotalPercentage()}%
                </p>
              </div>
              <Percent className="h-8 w-8 text-primary-500" />
            </div>
          </div>
          
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Fixed Amount</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                  ₹{getTotalFixedAmount().toLocaleString('en-IN')}
                </p>
              </div>
              <DollarSign className="h-8 w-8 text-secondary-500" />
            </div>
          </div>
        </div>
      )}

      {/* Categories Grid */}
      {categories.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {categories.map(category => (
            <div key={category.id} className="card">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div 
                    className="w-4 h-4 rounded-full"
                    style={{ backgroundColor: category.color }}
                  />
                  <h3 className="font-semibold text-gray-900 dark:text-gray-100">
                    {category.name}
                  </h3>
                </div>
                
                <div className="flex items-center space-x-1">
                  <button
                    onClick={() => handleEdit(category)}
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                  >
                    <Edit2 className="h-4 w-4 text-gray-500" />
                  </button>
                  <button
                    onClick={() => handleDelete(category)}
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                  >
                    <Trash2 className="h-4 w-4 text-danger-500" />
                  </button>
                </div>
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Balance:</span>
                  <span className="font-medium text-gray-900 dark:text-gray-100">
                    ₹{(category.current_balance || 0).toLocaleString('en-IN')}
                  </span>
                </div>
                
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Allocation:</span>
                  <span className="text-sm text-gray-900 dark:text-gray-100">
                    {category.percentage > 0 
                      ? `${category.percentage}% of salary`
                      : `₹${(category.fixed_amount || 0).toLocaleString('en-IN')} fixed`
                    }
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card text-center py-12">
          <div className="h-12 w-12 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
            <Plus className="h-6 w-6 text-gray-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
            No categories yet
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Create your first category to start organizing your finances
          </p>
          <button
            onClick={() => setShowForm(true)}
            className="btn-primary"
          >
            <Plus className="h-4 w-4 mr-2" />
            Create Category
          </button>
        </div>
      )}

      {/* Form Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl max-w-md w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                {editingCategory ? 'Edit Category' : 'Create Category'}
              </h3>

              <form onSubmit={handleSubmit} className="space-y-4">
                {formError && (
                  <div className="flex items-center space-x-2 p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
                    <AlertCircle className="h-5 w-5 text-danger-500" />
                    <p className="text-sm text-danger-700 dark:text-danger-400">{formError}</p>
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Category Name
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleFormChange}
                    className="input w-full"
                    placeholder="e.g., Food, Rent, Entertainment"
                    disabled={formLoading}
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Percentage (%)
                    </label>
                    <input
                      type="number"
                      name="percentage"
                      value={formData.percentage}
                      onChange={handleFormChange}
                      className="input w-full"
                      placeholder="0"
                      min="0"
                      max="100"
                      step="0.1"
                      disabled={formLoading}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Fixed Amount (₹)
                    </label>
                    <input
                      type="number"
                      name="fixed_amount"
                      value={formData.fixed_amount}
                      onChange={handleFormChange}
                      className="input w-full"
                      placeholder="0"
                      min="0"
                      step="0.01"
                      disabled={formLoading}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Color
                  </label>
                  <div className="grid grid-cols-6 gap-2">
                    {colors.map(color => (
                      <button
                        key={color}
                        type="button"
                        onClick={() => setFormData(prev => ({ ...prev, color }))}
                        className={`w-8 h-8 rounded-full border-2 ${
                          formData.color === color 
                            ? 'border-gray-900 dark:border-gray-100' 
                            : 'border-gray-300 dark:border-gray-600'
                        }`}
                        style={{ backgroundColor: color }}
                        disabled={formLoading}
                      />
                    ))}
                  </div>
                </div>

                <div className="flex items-center justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={resetForm}
                    className="btn-outline"
                    disabled={formLoading}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn-primary"
                    disabled={formLoading}
                  >
                    {formLoading ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                        Saving...
                      </>
                    ) : (
                      editingCategory ? 'Update' : 'Create'
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Categories