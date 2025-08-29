import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'

// Global styles
import './index.css'

// Polyfills for crypto operations
import { Buffer } from 'buffer'

// Make Buffer available globally for crypto operations
window.Buffer = Buffer

// Register service worker for PWA functionality
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then((registration) => {
        console.log('SW registered: ', registration)
      })
      .catch((registrationError) => {
        console.log('SW registration failed: ', registrationError)
      })
  })
}

// Error reporting for unhandled errors
window.addEventListener('error', (event) => {
  console.error('Unhandled error:', event.error)
  // In production, you might want to send this to an error reporting service
})

window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason)
  // In production, you might want to send this to an error reporting service
})

// Initialize React app
const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
)

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
