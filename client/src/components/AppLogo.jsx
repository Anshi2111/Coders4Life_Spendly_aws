import logoImage from '../assets/logo.svg'

function AppLogo({ showImage = true, size = 'default' }) {
  const sizeClasses = {
    small: 'h-8 w-8',
    default: 'h-10 w-10',
    large: 'h-12 w-12'
  }

  const textSizeClasses = {
    small: 'text-lg',
    default: 'text-xl',
    large: 'text-2xl'
  }

  const taglineSizeClasses = {
    small: 'text-xs',
    default: 'text-sm',
    large: 'text-base'
  }

  return (
    <div className="flex items-center space-x-3">
      {showImage && (
        <img 
          src={logoImage} 
          alt="Spendly Logo" 
          className={`${sizeClasses[size]} object-contain`}
        />
      )}
      <div className="flex flex-col">
        <h1 className={`${textSizeClasses[size]} font-bold text-teal-600 dark:text-teal-400 leading-tight`}>
          Spendly
        </h1>
        <p className={`${taglineSizeClasses[size]} text-gray-500 dark:text-gray-400 leading-tight`}>
          Track • Save • Grow
        </p>
      </div>
    </div>
  )
}

export default AppLogo