import { useState } from 'react'
import { Outlet, Link, useLocation } from 'react-router-dom'
import { 
  Home, 
  Receipt, 
  PieChart, 
  Target, 
  User, 
  Sun, 
  Moon,
  LogOut,
  HelpCircle
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'
import AppLogo from './AppLogo'

function Layout() {
  const { user, logout } = useAuth()
  const { isDark, toggleTheme } = useTheme()
  const location = useLocation()

  const navigation = [
    { name: 'Home', href: '/home', icon: Home, shortName: 'Home' },
    { name: 'Transactions', href: '/transactions', icon: Receipt, shortName: 'Transactions' },
    { name: 'Analytics', href: '/analytics', icon: PieChart, shortName: 'Analytics' },
    { name: 'How App Works', href: '/how-app-works', icon: HelpCircle, shortName: 'How It Works' },
    { name: 'Budget', href: '/budget-planning', icon: Target, shortName: 'Budget' },
    { name: 'Profile', href: '/profile', icon: User, shortName: 'Profile' },
  ]

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 overflow-x-hidden">
      {/* Desktop Top Navigation */}
      <nav className="hidden lg:block bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center">
              <AppLogo size="small" showImage={true} />
            </div>

            {/* Desktop Navigation */}
            <div className="flex items-baseline space-x-4">
              {navigation.map((item) => {
                const Icon = item.icon
                const isActive = location.pathname === item.href
                
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    className={`
                      flex items-center space-x-2 px-3 py-2 rounded-xl text-sm font-medium transition-all duration-200
                      ${isActive 
                        ? 'text-white shadow-brand' 
                        : 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700'
                      }
                    `}
                    style={isActive ? {
                      background: 'linear-gradient(135deg, #0891B2 0%, #059669 50%, #2563EB 100%)'
                    } : {}}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{item.name}</span>
                  </Link>
                )
              })}
            </div>

            {/* Right side - User menu and theme toggle */}
            <div className="flex items-center space-x-4">
              <button
                onClick={toggleTheme}
                className="p-2 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              >
                {isDark ? (
                  <Sun className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                ) : (
                  <Moon className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                )}
              </button>

              {/* User dropdown */}
              <div className="flex items-center space-x-3">
                <div className="h-8 w-8 bg-gradient-to-br from-primary-500 to-secondary-500 rounded-full flex items-center justify-center shadow-sm">
                  <span className="text-xs font-bold text-white">
                    {user?.name?.charAt(0)?.toUpperCase() || user?.email?.charAt(0)?.toUpperCase() || 'U'}
                  </span>
                </div>
                <div className="hidden xl:block">
                  <p className="text-sm font-medium text-gray-900 dark:text-gray-100 max-w-32 truncate">
                    {user?.name || 'User'}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400 max-w-32 truncate">
                    {user?.email}
                  </p>
                </div>
                <button
                  onClick={logout}
                  className="p-2 text-gray-400 hover:text-danger-500 transition-colors"
                  title="Logout"
                >
                  <LogOut className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Mobile Header */}
      <header className="lg:hidden bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 sticky top-0 z-40">
        <div className="flex items-center justify-between px-4 py-3">
          <AppLogo size="small" showImage={true} />
          <div className="flex items-center space-x-2">
            <button
              onClick={toggleTheme}
              className="p-2 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            >
              {isDark ? (
                <Sun className="h-5 w-5 text-gray-600 dark:text-gray-400" />
              ) : (
                <Moon className="h-5 w-5 text-gray-600 dark:text-gray-400" />
              )}
            </button>
            <div className="h-8 w-8 bg-gradient-to-br from-primary-500 to-secondary-500 rounded-full flex items-center justify-center shadow-sm">
              <span className="text-xs font-bold text-white">
                {user?.name?.charAt(0)?.toUpperCase() || user?.email?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main content with bottom padding for mobile nav */}
      <main className="flex-1 pb-16 lg:pb-0">
        <Outlet />
      </main>

      {/* Mobile Bottom Navigation */}
      <nav className="lg:hidden fixed bottom-0 left-0 right-0 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 z-50 safe-area-inset-bottom">
        <div className="grid grid-cols-6 h-16">
          {navigation.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.href
            
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`
                  flex flex-col items-center justify-center space-y-1 py-2 px-1 transition-all duration-200 min-h-[44px]
                  ${isActive 
                    ? 'text-primary-600 dark:text-primary-400' 
                    : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                  }
                `}
              >
                <Icon className={`h-5 w-5 ${isActive ? 'text-primary-600 dark:text-primary-400' : ''}`} />
                <span className={`text-xs font-medium leading-none max-w-full truncate ${isActive ? 'text-primary-600 dark:text-primary-400' : ''}`}>
                  {item.shortName}
                </span>
              </Link>
            )
          })}
        </div>
      </nav>
    </div>
  )
}

export default Layout