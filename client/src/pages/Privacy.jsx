import React from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Wallet, Shield } from 'lucide-react'

function Privacy() {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="flex items-center space-x-2">
              <Wallet className="h-12 w-12 text-primary-500" />
              <Shield className="h-8 w-8 text-secondary-500" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Privacy Policy
          </h1>
          <p className="mt-2 text-gray-600 dark:text-gray-400">
            Last updated: {new Date().toLocaleDateString()}
          </p>
        </div>

        {/* Content */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-8">
          <div className="prose prose-gray dark:prose-invert max-w-none">
            <h2>1. Information We Collect</h2>
            
            <h3>Personal Information</h3>
            <p>When you create an account, we collect:</p>
            <ul>
              <li>Email address (for account identification)</li>
              <li>Name (for personalization)</li>
              <li>Salary information (for budget calculations)</li>
            </ul>

            <h3>Financial Data</h3>
            <p>We store minimal financial information:</p>
            <ul>
              <li>Budget categories and allocations</li>
              <li>Transaction records (amount, merchant name, category, status)</li>
              <li>Category balances and spending history</li>
            </ul>

            <h3>What We DO NOT Collect</h3>
            <div className="bg-danger-50 dark:bg-danger-900/20 p-4 rounded-lg">
              <p className="text-danger-700 dark:text-danger-300 font-semibold">
                We never collect or store:
              </p>
              <ul className="text-danger-700 dark:text-danger-300">
                <li>Bank account numbers or details</li>
                <li>UPI PINs or passwords</li>
                <li>Credit/debit card information</li>
                <li>Banking app credentials</li>
                <li>Actual payment processing data</li>
              </ul>
            </div>

            <h2>2. How We Use Your Information</h2>
            <p>Your information is used to:</p>
            <ul>
              <li>Provide and maintain the Spendly service</li>
              <li>Calculate budget allocations and track spending</li>
              <li>Generate UPI payment intents (redirects to your UPI apps)</li>
              <li>Provide customer support</li>
              <li>Improve our services and user experience</li>
            </ul>

            <h2>3. Payment Processing</h2>
            <p>
              <strong>Spendly does not process payments.</strong> Here's how payments work:
            </p>
            <ol>
              <li>You initiate a payment through Spendly</li>
              <li>We generate a UPI intent URL with payment details</li>
              <li>Your device redirects to your installed UPI app (Google Pay, PhonePe, etc.)</li>
              <li>The UPI app handles the actual payment processing</li>
              <li>You manually update the transaction status in Spendly</li>
            </ol>
            
            <div className="bg-secondary-50 dark:bg-secondary-900/20 p-4 rounded-lg">
              <p className="text-secondary-700 dark:text-secondary-300">
                <strong>Security Note:</strong> Since we don't process payments, we never have access to your 
                banking credentials or payment methods. All sensitive payment data remains with your UPI service provider.
              </p>
            </div>

            <h2>4. Data Storage and Security</h2>
            <p>We implement security measures including:</p>
            <ul>
              <li>Encrypted data transmission (HTTPS)</li>
              <li>Secure password hashing</li>
              <li>JWT-based authentication</li>
              <li>Regular security updates</li>
              <li>Limited data retention policies</li>
            </ul>

            <h2>5. Data Sharing</h2>
            <p>
              <strong>We do not sell, trade, or share your personal information with third parties</strong> except:
            </p>
            <ul>
              <li>When required by law or legal process</li>
              <li>To protect our rights or the safety of users</li>
              <li>With your explicit consent</li>
            </ul>

            <h2>6. Your Rights</h2>
            <p>You have the right to:</p>
            <ul>
              <li>Access your personal data</li>
              <li>Correct inaccurate information</li>
              <li>Delete your account and associated data</li>
              <li>Export your data</li>
              <li>Withdraw consent for data processing</li>
            </ul>

            <h2>7. Data Retention</h2>
            <p>We retain your data:</p>
            <ul>
              <li>As long as your account is active</li>
              <li>For up to 30 days after account deletion (for recovery purposes)</li>
              <li>As required by applicable laws and regulations</li>
            </ul>

            <h2>8. Children's Privacy</h2>
            <p>
              Spendly is not intended for users under 18 years of age. We do not knowingly collect 
              personal information from children under 18.
            </p>

            <h2>9. International Data Transfers</h2>
            <p>
              Your data is primarily stored and processed in India. If data is transferred internationally, 
              we ensure appropriate safeguards are in place.
            </p>

            <h2>10. Changes to Privacy Policy</h2>
            <p>
              We may update this privacy policy from time to time. We will notify users of significant 
              changes through the app or email.
            </p>

            <h2>11. Contact Us</h2>
            <p>
              For privacy-related questions or to exercise your rights, contact us through:
            </p>
            <ul>
              <li>In-app support</li>
              <li>Email: privacy@spendly.app</li>
            </ul>

            <div className="mt-8 p-4 bg-primary-50 dark:bg-primary-900/20 rounded-lg">
              <p className="text-sm text-primary-700 dark:text-primary-300">
                <strong>Transparency Commitment:</strong> We believe in complete transparency about data handling. 
                If you have any questions about how your data is used, please don't hesitate to contact us.
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div className="mt-8 flex items-center justify-between">
          <Link 
            to="/terms" 
            className="flex items-center space-x-2 text-primary-600 hover:text-primary-500 dark:text-primary-400"
          >
            <ArrowLeft className="h-4 w-4" />
            <span>Terms of Service</span>
          </Link>
          
          <Link 
            to="/login" 
            className="text-primary-600 hover:text-primary-500 dark:text-primary-400"
          >
            Back to Login →
          </Link>
        </div>
      </div>
    </div>
  )
}

export default Privacy