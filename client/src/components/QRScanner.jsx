import React, { useEffect, useRef, useState } from 'react'
import { Html5QrcodeScanner } from 'html5-qrcode'
import { X, Camera, AlertCircle, Loader2 } from 'lucide-react'

function QRScanner({ isOpen, onClose, onScan }) {
  const scannerRef = useRef(null)
  const [error, setError] = useState(null)
  const [isScanning, setIsScanning] = useState(false)
  const [permissionState, setPermissionState] = useState('requesting') // 'requesting', 'granted', 'denied', 'blocked'
  const [isInitializing, setIsInitializing] = useState(false)

  useEffect(() => {
    if (!isOpen) return

    let scanner = null

    const checkCameraPermission = async () => {
      try {
        // Check if HTTPS is enabled (required for camera access in production)
        if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
          setError('Camera access requires HTTPS connection. Please use a secure connection.')
          setPermissionState('blocked')
          return false
        }

        // Check if getUserMedia is supported
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
          setError('Camera access is not supported on this device or browser.')
          setPermissionState('blocked')
          return false
        }

        return true
      } catch (err) {
        console.error('❌ Camera permission check failed:', err)
        setError('Failed to check camera permissions.')
        setPermissionState('blocked')
        return false
      }
    }

    const requestCameraPermission = async () => {
      try {
        setIsInitializing(true)
        setError(null)
        setPermissionState('requesting')

        // Request camera permission explicitly
        const stream = await navigator.mediaDevices.getUserMedia({ 
          video: { 
            facingMode: 'environment' // Prefer back camera on mobile
          } 
        })
        
        // Stop the stream immediately - we just needed permission
        stream.getTracks().forEach(track => track.stop())
        
        setPermissionState('granted')
        return true
      } catch (err) {
        console.error('❌ Camera permission denied:', err)
        
        if (err.name === 'NotAllowedError') {
          setError('Camera permission denied. Please allow camera access and try again.')
          setPermissionState('denied')
        } else if (err.name === 'NotFoundError') {
          setError('No camera found on this device.')
          setPermissionState('blocked')
        } else if (err.name === 'NotSupportedError') {
          setError('Camera access is not supported on this device.')
          setPermissionState('blocked')
        } else {
          setError('Failed to access camera. Please check your browser settings.')
          setPermissionState('blocked')
        }
        
        return false
      } finally {
        setIsInitializing(false)
      }
    }

    const initScanner = async () => {
      try {
        setError(null)
        setIsScanning(true)

        // Wait for DOM element to be available
        const qrReaderElement = document.getElementById('qr-reader')
        if (!qrReaderElement) {
          console.error('❌ QR reader element not found')
          setError('Failed to initialize QR scanner. Please try again.')
          setIsScanning(false)
          return
        }

        // Create scanner with production-ready configuration
        scanner = new Html5QrcodeScanner(
          "qr-reader",
          {
            fps: 10,
            qrbox: { width: 250, height: 250 },
            aspectRatio: 1.0,
            showTorchButtonIfSupported: true,
            showZoomSliderIfSupported: true,
            defaultZoomValueIfSupported: 2,
            rememberLastUsedCamera: true,
            supportedScanTypes: [Html5QrcodeScanner.SCAN_TYPE_CAMERA]
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
                // Clean up scanner before closing
                if (scanner) {
                  scanner.clear().catch(console.error)
                }
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
            // Ignore frequent scanning errors but log others
            if (!errorMessage.includes('No MultiFormat Readers') && 
                !errorMessage.includes('NotFoundException')) {
              console.log('QR scan error:', errorMessage)
            }
          }
        )
      } catch (err) {
        console.error('❌ Scanner initialization error:', err)
        setError('Failed to initialize QR scanner. Please try again.')
        setIsScanning(false)
      }
    }

    const startScanning = async () => {
      // Check camera support and permissions
      const hasSupport = await checkCameraPermission()
      if (!hasSupport) return

      // Request permission
      const hasPermission = await requestCameraPermission()
      if (!hasPermission) return

      // Wait a bit for DOM to be ready
      setTimeout(() => {
        initScanner()
      }, 100)
    }

    startScanning()

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

  const handleRetry = () => {
    setError(null)
    setPermissionState('requesting')
    // Re-trigger the effect by toggling a state
    window.location.reload()
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

          {/* Permission/Error States */}
          {isInitializing && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
              <span className="ml-2 text-gray-600 dark:text-gray-400">
                Requesting camera access...
              </span>
            </div>
          )}

          {error && (
            <div className="mb-4 p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
              <div className="flex items-start space-x-2">
                <AlertCircle className="h-5 w-5 text-danger-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm text-danger-700 dark:text-danger-400">{error}</p>
                  {permissionState === 'denied' && (
                    <div className="mt-2">
                      <p className="text-xs text-danger-600 dark:text-danger-500">
                        To enable camera access:
                      </p>
                      <ul className="text-xs text-danger-600 dark:text-danger-500 mt-1 list-disc list-inside">
                        <li>Click the camera icon in your browser's address bar</li>
                        <li>Select "Allow" for camera permission</li>
                        <li>Refresh the page and try again</li>
                      </ul>
                    </div>
                  )}
                  {(permissionState === 'denied' || permissionState === 'blocked') && (
                    <button
                      onClick={handleRetry}
                      className="mt-2 text-xs bg-danger-100 hover:bg-danger-200 text-danger-700 px-2 py-1 rounded"
                    >
                      Try Again
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Scanner Container */}
          {permissionState === 'granted' && !error && (
            <div 
              id="qr-reader" 
              className="w-full"
              style={{ minHeight: '300px' }}
            />
          )}

          {/* Loading State */}
          {permissionState === 'requesting' && !isInitializing && !error && (
            <div className="flex items-center justify-center py-8">
              <div className="text-center">
                <Camera className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Initializing camera...
                </p>
              </div>
            </div>
          )}

          {/* Help Text */}
          {permissionState === 'granted' && !error && (
            <div className="mt-4 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Make sure the QR code is well-lit and clearly visible
              </p>
            </div>
          )}
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