import React from 'react'
import { Wallet } from 'lucide-react'

const SpendlyLogo = ({ size = 'md', showText = true, showTagline = false, className = '' }) => {
  const sizeClasses = {
    sm: {
      icon: 'h-6 w-6',
      text: 'text-lg',
      tagline: 'text-xs'
    },
    md: {
      icon: 'h-8 w-8',
      text: 'text-xl',
      tagline: 'text-sm'
    },
    lg: {
      icon: 'h-12 w-12',
      text: 'text-3xl',
      tagline: 'text-base'
    },
    xl: {
      icon: 'h-16 w-16',
      text: 'text-4xl',
      tagline: 'text-lg'
    }
  }

  const currentSize = sizeClasses[size] || sizeClasses.md

  return (
    <div className={`flex items-center space-x-3 ${className}`}>
      {/* Logo Icon */}
      <div className="relative">
        <div className={`${currentSize.icon} bg-gradient-brand rounded-xl flex items-center justify-center shadow-brand`}>
          <Wallet className={`${size === 'sm' ? 'h-3 w-3' : size === 'lg' ? 'h-6 w-6' : size === 'xl' ? 'h-8 w-8' : 'h-4 w-4'} text-white`} />
        </div>
        
        {/* Dollar coin overlay */}
        <div className={`absolute -top-1 -right-1 ${size === 'sm' ? 'h-3 w-3' : size === 'lg' ? 'h-5 w-5' : size === 'xl' ? 'h-6 w-6' : 'h-4 w-4'} bg-gradient-to-br from-accent-400 to-accent-600 rounded-full flex items-center justify-center shadow-sm`}>
          <span className={`${size === 'sm' ? 'text-[8px]' : size === 'lg' ? 'text-xs' : size === 'xl' ? 'text-sm' : 'text-[10px]'} font-bold text-white`}>
            ₹
          </span>
        </div>
      </div>

      {/* Logo Text */}
      {showText && (
        <div className="flex flex-col">
          <h1 className={`${currentSize.text} font-bold logo-text leading-none`}>
            Spendly
          </h1>
          {showTagline && (
            <p className={`${currentSize.tagline} text-gray-600 dark:text-gray-400 font-medium tracking-wide`}>
              Track • Save • Grow
            </p>
          )}
        </div>
      )}
    </div>
  )
}

export default SpendlyLogo