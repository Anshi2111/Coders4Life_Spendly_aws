import React, { useState, useEffect } from 'react'
import { CheckCircle, XCircle, AlertTriangle, X } from 'lucide-react'

const Toast = ({ type = 'success', message, isVisible, onClose, duration = 4000 }) => {
  useEffect(() => {
    if (isVisible && duration > 0) {
      const timer = setTimeout(() => {
        onClose()
      }, duration)
      
      return () => clearTimeout(timer)
    }
  }, [isVisible, duration, onClose])

  if (!isVisible) return null

  const getIcon = () => {
    switch (type) {
      case 'success':
        return <CheckCircle className="h-5 w-5 text-success-500" />
      case 'error':
        return <XCircle className="h-5 w-5 text-danger-500" />
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-warning-500" />
      default:
        return <CheckCircle className="h-5 w-5 text-success-500" />
    }
  }

  const getToastClass = () => {
    switch (type) {
      case 'success':
        return 'toast-success'
      case 'error':
        return 'toast-error'
      case 'warning':
        return 'toast-warning'
      default:
        return 'toast-success'
    }
  }

  return (
    <div className={getToastClass()}>
      <div className="flex items-start space-x-3">
        <div className="flex-shrink-0">
          {getIcon()}
        </div>
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {message}
          </p>
        </div>
        <button
          onClick={onClose}
          className="flex-shrink-0 p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md transition-colors"
        >
          <X className="h-4 w-4 text-gray-400" />
        </button>
      </div>
    </div>
  )
}

// Toast Hook
export const useToast = () => {
  const [toasts, setToasts] = useState([])

  const showToast = (message, type = 'success', duration = 4000) => {
    const id = Date.now()
    const toast = { id, message, type, duration }
    
    setToasts(prev => [...prev, toast])
    
    // Auto remove after duration
    if (duration > 0) {
      setTimeout(() => {
        removeToast(id)
      }, duration)
    }
    
    return id
  }

  const removeToast = (id) => {
    setToasts(prev => prev.filter(toast => toast.id !== id))
  }

  const success = (message, duration) => showToast(message, 'success', duration)
  const error = (message, duration) => showToast(message, 'error', duration)
  const warning = (message, duration) => showToast(message, 'warning', duration)

  return {
    toasts,
    showToast,
    removeToast,
    success,
    error,
    warning
  }
}

// Toast Container Component
export const ToastContainer = () => {
  const { toasts, removeToast } = useToast()

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      {toasts.map(toast => (
        <Toast
          key={toast.id}
          type={toast.type}
          message={toast.message}
          isVisible={true}
          onClose={() => removeToast(toast.id)}
          duration={0} // Handled by useToast hook
        />
      ))}
    </div>
  )
}

export default Toast