import React from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { ThemeProvider } from './contexts/ThemeContext'
import { BalanceProvider } from './contexts/BalanceContext'
import Layout from './components/Layout'
import Login from './pages/Login'
import Register from './pages/Register'
import ForgotPassword from './pages/ForgotPassword'
import Home from './pages/Home'
import Dashboard from './pages/Dashboard'
import Analytics from './pages/Analytics'
import HowAppWorks from './pages/HowAppWorks'
import BudgetPlanning from './pages/BudgetPlanning'
import Categories from './pages/Categories'
import Transactions from './pages/Transactions'
import Profile from './pages/Profile'
import Terms from './pages/Terms'
import Privacy from './pages/Privacy'
import ErrorBoundary from './components/ErrorBoundary'

// Protected Route Component
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </div>
    )
  }
  
  return user ? children : <Navigate to="/login" replace />
}

// Public Route Component (redirect if authenticated)
function PublicRoute({ children }) {
  const { user, loading } = useAuth()
  
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </div>
    )
  }
  
  return user ? <Navigate to="/home" replace /> : children
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <AuthProvider>
          <BalanceProvider>
            <Router>
              <Routes>
                {/* Public Routes */}
                <Route path="/terms" element={<Terms />} />
                <Route path="/privacy" element={<Privacy />} />
                
                <Route path="/login" element={
                  <PublicRoute>
                    <Login />
                  </PublicRoute>
                } />
                
                <Route path="/register" element={
                  <PublicRoute>
                    <Register />
                  </PublicRoute>
                } />
                
                <Route path="/forgot-password" element={
                  <PublicRoute>
                    <ForgotPassword />
                  </PublicRoute>
                } />
                
                {/* Protected Routes */}
                <Route path="/" element={
                  <ProtectedRoute>
                    <Layout />
                  </ProtectedRoute>
                }>
                  <Route index element={<Navigate to="/home" replace />} />
                  <Route path="home" element={<Home />} />
                  <Route path="dashboard" element={<Dashboard />} />
                  <Route path="analytics" element={<Analytics />} />
                  <Route path="how-app-works" element={<HowAppWorks />} />
                  <Route path="budget-planning" element={<BudgetPlanning />} />
                  <Route path="categories" element={<Categories />} />
                  <Route path="transactions" element={<Transactions />} />
                  <Route path="profile" element={<Profile />} />
                </Route>
                
                {/* Catch all route */}
                <Route path="*" element={<Navigate to="/home" replace />} />
              </Routes>
            </Router>
          </BalanceProvider>
        </AuthProvider>
      </ThemeProvider>
    </ErrorBoundary>
  )
}

export default App