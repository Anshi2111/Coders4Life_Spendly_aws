import React, { useEffect, useRef, useState } from 'react'
import { Html5QrcodeScanner } from 'html5-qrcode'
import { X, Camera } from 'lucide-react'

function QRScanner({ isOpen, onClose, onScan }) {
  const scannerRef = useRef(null)
  const [error, setError] = useState(null)
  const [isScanning, setIsScanning] = useState(false)

  useEffect(() => {
    if (!isOpen) return

    let scanner = null

    const initScanner = async () => {
      try {
        setError(null)
        setIsScanning(true)

        scanner = new Html5QrcodeScanner(
          "qr-reader",
          {
            fps: 10,
            qrbox: { width: 250, height: 250 },
            aspectRatio: 1.0,
            showTorchButtonIfSupported: true,
            showZoomSliderIfSupported: true,
            defaultZoomValueIfSupported: 2,
          },
          false
        )

        scanner.render(
          (decodedText, decodedResult) => {
            console.log('✅ QR Code scanned:', decodedText)
            
            // Parse UPI URL
            try {
              const upiData = parseUPIUrl(decodedText)
              if (upiData) {
                onScan(upiData)
                scanner?.clear()
                onClose()
              } else {
                setError('Invalid QR code. Please scan a UPI payment QR code.')
              }
            } catch (err) {
              console.error('❌ QR parsing error:', err)
              setError('Failed to parse QR code data.')
            }
          },
          (errorMessage) => {
            // Ignore frequent scanning errors
            if (!errorMessage.includes('No MultiFormat Readers')) {
              console.log('QR scan error:', errorMessage)
            }
          }
        )
      } catch (err) {
        console.error('❌ Scanner initialization error:', err)
        setError('Failed to initialize camera. Please check permissions.')
      }
    }

    initScanner()

    return () => {
      if (scanner) {
        scanner.clear().catch(console.error)
      }
    }
  }, [isOpen, onScan, onClose])

  const parseUPIUrl = (url) => {
    try {
      // Handle both upi:// and plain text UPI IDs
      if (url.startsWith('upi://pay?')) {
        const urlObj = new URL(url)
        const params = urlObj.searchParams
        
        return {
          upiId: params.get('pa'),
          merchantName: params.get('pn') || 'Unknown Merchant',
          amount: params.get('am') || '',
          note: params.get('tn') || ''
        }
      } else if (url.includes('@')) {
        // Plain UPI ID
        return {
          upiId: url.trim(),
          merchantName: 'Scanned Merchant',
          amount: '',
          note: ''
        }
      }
      
      return null
    } catch (error) {
      console.error('❌ UPI URL parsing error:', error)
      return null
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 bg-black bg-opacity-75 flex items-center justify-center p-4">
      <div className="bg-white dark:bg-gray-800 rounded-xl max-w-md w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-2">
            <Camera className="h-5 w-5 text-primary-500" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Scan QR Code
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scanner */}
        <div className="p-4">
          <div className="text-center mb-4">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Point your camera at a UPI QR code to scan
            </p>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
              <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
            </div>
          )}

          <div 
            id="qr-reader" 
            className="w-full"
            style={{ minHeight: '300px' }}
          />

          <div className="mt-4 text-center">
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Make sure the QR code is well-lit and clearly visible
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <button
            onClick={onClose}
            className="btn-outline w-full"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

export default QRScanner