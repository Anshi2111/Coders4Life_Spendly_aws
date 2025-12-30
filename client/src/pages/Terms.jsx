import React from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Wallet } from 'lucide-react'

function Terms() {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <Wallet className="h-12 w-12 text-primary-500" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Terms of Service
          </h1>
          <p className="mt-2 text-gray-600 dark:text-gray-400">
            Last updated: {new Date().toLocaleDateString()}
          </p>
        </div>

        {/* Content */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-8">
          <div className="prose prose-gray dark:prose-invert max-w-none">
            <h2>1. Acceptance of Terms</h2>
            <p>
              By accessing and using Spendly ("the Service"), you accept and agree to be bound by the terms and provision of this agreement.
            </p>

            <h2>2. Description of Service</h2>
            <p>
              Spendly is a personal finance management application that helps users:
            </p>
            <ul>
              <li>Organize income into customizable spending categories</li>
              <li>Track expenses and maintain budgets</li>
              <li>Facilitate UPI payments through existing payment apps</li>
              <li>Monitor financial transactions and balances</li>
            </ul>

            <h2>3. User Responsibilities</h2>
            <p>You agree to:</p>
            <ul>
              <li>Provide accurate and complete information when creating your account</li>
              <li>Maintain the security of your account credentials</li>
              <li>Use the Service only for lawful purposes</li>
              <li>Not attempt to gain unauthorized access to the Service or other users' accounts</li>
              <li>Comply with all applicable laws and regulations</li>
            </ul>

            <h2>4. Payment Processing</h2>
            <p>
              <strong>Important:</strong> Spendly does not process payments directly. We:
            </p>
            <ul>
              <li>Generate UPI payment intents that redirect to your installed UPI apps</li>
              <li>Do not store or access your bank account details, UPI PIN, or payment credentials</li>
              <li>Only track transaction status for budget management purposes</li>
              <li>Are not responsible for payment failures or issues with UPI service providers</li>
            </ul>

            <h2>5. Data Privacy and Security</h2>
            <p>We are committed to protecting your privacy:</p>
            <ul>
              <li>We do not store sensitive financial information like bank account numbers or UPI PINs</li>
              <li>Transaction data is stored locally and used only for budget tracking</li>
              <li>We implement industry-standard security measures to protect your data</li>
              <li>See our Privacy Policy for detailed information about data handling</li>
            </ul>

            <h2>6. Limitations of Liability</h2>
            <p>
              Spendly is provided "as is" without warranties of any kind. We are not liable for:
            </p>
            <ul>
              <li>Payment failures or errors in UPI transactions</li>
              <li>Financial losses resulting from app usage</li>
              <li>Service interruptions or technical issues</li>
              <li>Inaccuracies in budget calculations or financial data</li>
            </ul>

            <h2>7. Account Termination</h2>
            <p>
              We reserve the right to terminate or suspend accounts that violate these terms. You may delete your account at any time through the app settings.
            </p>

            <h2>8. Changes to Terms</h2>
            <p>
              We may update these terms from time to time. Continued use of the Service after changes constitutes acceptance of the new terms.
            </p>

            <h2>9. Governing Law</h2>
            <p>
              These terms are governed by the laws of India. Any disputes will be resolved in the courts of India.
            </p>

            <h2>10. Contact Information</h2>
            <p>
              For questions about these terms, please contact us through the app or at our support channels.
            </p>

            <div className="mt-8 p-4 bg-primary-50 dark:bg-primary-900/20 rounded-lg">
              <p className="text-sm text-primary-700 dark:text-primary-300">
                <strong>Disclaimer:</strong> Spendly is a budget management tool. We do not provide financial advice. 
                Always consult with qualified financial professionals for investment and financial planning decisions.
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div className="mt-8 flex items-center justify-between">
          <Link 
            to="/login" 
            className="flex items-center space-x-2 text-primary-600 hover:text-primary-500 dark:text-primary-400"
          >
            <ArrowLeft className="h-4 w-4" />
            <span>Back to Login</span>
          </Link>
          
          <Link 
            to="/privacy" 
            className="text-primary-600 hover:text-primary-500 dark:text-primary-400"
          >
            Privacy Policy →
          </Link>
        </div>
      </div>
    </div>
  )
}

export default Terms