import { 
  Smartphone, 
  Wallet, 
  PieChart, 
  Send, 
  Shield, 
  Target,
  CheckCircle,
  QrCode,
  TrendingUp
} from 'lucide-react'
import AppLogo from '../components/AppLogo'

function HowAppWorks() {
  const steps = [
    {
      icon: Wallet,
      title: "Set Your Salary",
      description: "Enter your monthly salary to create your budget foundation",
      color: "bg-primary-500"
    },
    {
      icon: PieChart,
      title: "Create Categories",
      description: "Divide your salary into spending categories like Food, Transport, etc.",
      color: "bg-secondary-500"
    },
    {
      icon: Send,
      title: "Make Payments",
      description: "Pay directly from categories using UPI without storing bank details",
      color: "bg-accent-500"
    },
    {
      icon: TrendingUp,
      title: "Track & Analyze",
      description: "Monitor spending patterns and optimize your budget with insights",
      color: "bg-purple-500"
    }
  ]

  const features = [
    {
      icon: Shield,
      title: "Secure Payments",
      description: "We never store your bank details. All payments go through your UPI app.",
      color: "text-green-600"
    },
    {
      icon: QrCode,
      title: "QR Code Scanner",
      description: "Scan merchant QR codes to auto-fill payment details instantly.",
      color: "text-blue-600"
    },
    {
      icon: Target,
      title: "Budget Control",
      description: "Set spending limits per category and get alerts when you're close.",
      color: "text-purple-600"
    },
    {
      icon: TrendingUp,
      title: "Smart Analytics",
      description: "Visual charts and insights to understand your spending patterns.",
      color: "text-orange-600"
    }
  ]

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="text-center mb-12">
        <div className="flex justify-center mb-6">
          <AppLogo size="large" showImage={false} />
        </div>
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          How Spendly Works 🚀
        </h1>
        <p className="text-xl text-gray-600 dark:text-gray-400 max-w-3xl mx-auto">
          Your personal finance companion that helps you track, save, and grow your money with smart budgeting and secure UPI payments.
        </p>
      </div>

      {/* How It Works Steps */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 text-center mb-8">
          Get Started in 4 Simple Steps
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {steps.map((step, index) => {
            const Icon = step.icon
            return (
              <div key={index} className="text-center">
                <div className="relative mb-4">
                  <div className={`${step.color} w-16 h-16 rounded-2xl flex items-center justify-center mx-auto shadow-lg`}>
                    <Icon className="h-8 w-8 text-white" />
                  </div>
                  <div className="absolute -top-2 -right-2 bg-white dark:bg-gray-800 rounded-full w-8 h-8 flex items-center justify-center border-2 border-gray-200 dark:border-gray-600">
                    <span className="text-sm font-bold text-gray-900 dark:text-gray-100">{index + 1}</span>
                  </div>
                </div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  {step.title}
                </h3>
                <p className="text-gray-600 dark:text-gray-400 text-sm">
                  {step.description}
                </p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Key Features */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 text-center mb-8">
          Powerful Features
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {features.map((feature, index) => {
            const Icon = feature.icon
            return (
              <div key={index} className="card hover:shadow-lg transition-shadow">
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    <Icon className={`h-8 w-8 ${feature.color}`} />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                      {feature.title}
                    </h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      {feature.description}
                    </p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Security & Privacy */}
      <div className="card-brand mb-16">
        <div className="text-center">
          <Shield className="h-16 w-16 text-white mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-4">
            Your Security is Our Priority
          </h2>
          <p className="text-white/90 max-w-2xl mx-auto mb-6">
            Spendly never stores your bank account numbers, UPI PINs, or card details. 
            All payments are processed through your existing UPI apps like Google Pay, PhonePe, or Paytm.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-left">
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-6 w-6 text-white flex-shrink-0" />
              <span className="text-white/90">No bank details stored</span>
            </div>
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-6 w-6 text-white flex-shrink-0" />
              <span className="text-white/90">UPI app integration</span>
            </div>
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-6 w-6 text-white flex-shrink-0" />
              <span className="text-white/90">Secure data encryption</span>
            </div>
          </div>
        </div>
      </div>

      {/* Payment Flow */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 text-center mb-8">
          How Payments Work
        </h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="card text-center">
            <div className="bg-primary-100 dark:bg-primary-900/20 w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <QrCode className="h-8 w-8 text-primary-600 dark:text-primary-400" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              1. Scan or Enter UPI ID
            </h3>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              Use our QR scanner or manually enter the merchant's UPI ID
            </p>
          </div>

          <div className="card text-center">
            <div className="bg-secondary-100 dark:bg-secondary-900/20 w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <PieChart className="h-8 w-8 text-secondary-600 dark:text-secondary-400" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              2. Select Category & Amount
            </h3>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              Choose which budget category to pay from and enter the amount
            </p>
          </div>

          <div className="card text-center">
            <div className="bg-accent-100 dark:bg-accent-900/20 w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <Smartphone className="h-8 w-8 text-accent-600 dark:text-accent-400" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              3. Complete in UPI App
            </h3>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              Your UPI app opens automatically to complete the secure payment
            </p>
          </div>
        </div>
      </div>

      {/* FAQ */}
      <div className="card">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">
          Frequently Asked Questions
        </h2>
        
        <div className="space-y-6">
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              Is my money safe with Spendly?
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Absolutely! Spendly doesn't handle your money directly. We only track your budget and redirect you to your UPI app for payments. Your bank details never leave your device.
            </p>
          </div>
          
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              Which UPI apps are supported?
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Spendly works with all UPI apps including Google Pay, PhonePe, Paytm, BHIM, and any other UPI-enabled app on your device.
            </p>
          </div>
          
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              Can I use Spendly without making payments?
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Yes! You can use Spendly purely for budget tracking and expense analysis without making any payments through the app.
            </p>
          </div>
          
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              How does budget tracking work?
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Set your monthly salary, create spending categories with percentages or fixed amounts, and Spendly automatically tracks your remaining balance as you make payments.
            </p>
          </div>
        </div>
      </div>

      {/* Quick Payment Feature */}
      <div className="mt-16">
        <div className="card-brand">
          <div className="text-center mb-8">
            <Send className="h-16 w-16 text-white mx-auto mb-4" />
            <h2 className="text-3xl font-bold text-white mb-4">
              Quick Payment Feature 💳
            </h2>
            <p className="text-white/90 text-lg max-w-3xl mx-auto">
              Transform Spendly from a passive expense tracker into an intent-aware payment companion where you pay through budgets, not outside them.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            <div className="bg-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-white mb-4">
                🎯 Smart Category Selection
              </h3>
              <ul className="space-y-2 text-white/90">
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>View all budget categories with remaining balances</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>See saved UPI IDs and QR codes for quick access</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>Click any category to start instant payment</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>Automatic balance validation prevents overspending</span>
                </li>
              </ul>
            </div>

            <div className="bg-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-white mb-4">
                🔒 Secure Payment Flow
              </h3>
              <ul className="space-y-2 text-white/90">
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>Enter amount with real-time balance checking</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>Choose UPI ID entry or QR code scanning</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>Generate UPI intent URL for app redirection</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-white mt-0.5 flex-shrink-0" />
                  <span>Manual success confirmation after payment</span>
                </li>
              </ul>
            </div>
          </div>

          <div className="bg-white/10 rounded-xl p-6">
            <h3 className="text-xl font-semibold text-white mb-4 text-center">
              🛡️ Data & Security Rules
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="text-center">
                <Target className="h-8 w-8 text-white mx-auto mb-2" />
                <p className="text-white/90 text-sm">Categories are single source of truth for payments</p>
              </div>
              <div className="text-center">
                <Shield className="h-8 w-8 text-white mx-auto mb-2" />
                <p className="text-white/90 text-sm">Prevent payments if category balance insufficient</p>
              </div>
              <div className="text-center">
                <CheckCircle className="h-8 w-8 text-white mx-auto mb-2" />
                <p className="text-white/90 text-sm">Graceful API failure handling with fallbacks</p>
              </div>
              <div className="text-center">
                <QrCode className="h-8 w-8 text-white mx-auto mb-2" />
                <p className="text-white/90 text-sm">Never store bank details or UPI credentials</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default HowAppWorks