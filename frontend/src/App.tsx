import React, { Suspense, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { HelmetProvider } from 'react-helmet-async'
import { Toaster } from 'react-hot-toast'
import { AnimatePresence, motion } from 'framer-motion'

// Stores and Context
import { useAuthStore } from '@store/authStore'
import { useEncryptionStore } from '@store/encryptionStore'
import { useThemeStore } from '@store/themeStore'

// Layout Components
import Layout from '@components/Layout/Layout'
import LoadingSpinner from '@components/UI/LoadingSpinner'
import ErrorBoundary from '@components/ErrorBoundary/ErrorBoundary'

// Page Components (Lazy loaded for performance)
const WheelPage = React.lazy(() => import('@pages/WheelPage'))
const AuthPage = React.lazy(() => import('@pages/AuthPage'))
const DashboardPage = React.lazy(() => import('@pages/DashboardPage'))
const ProfilePage = React.lazy(() => import('@pages/ProfilePage'))
const JourneyPage = React.lazy(() => import('@pages/JourneyPage'))
const AnalyticsPage = React.lazy(() => import('@pages/AnalyticsPage'))
const SettingsPage = React.lazy(() => import('@pages/SettingsPage'))
const LandingPage = React.lazy(() => import('@pages/LandingPage'))

// Hooks and Utilities
import { useInitializeApp } from '@hooks/useInitializeApp'
import { initializeCrypto } from '@crypto/cryptoManager'

// Styles
import './App.css'

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      retry: (failureCount, error: any) => {
        // Don't retry on 401/403 errors
        if (error?.response?.status === 401 || error?.response?.status === 403) {
          return false
        }
        return failureCount < 3
      },
      refetchOnWindowFocus: false
    },
    mutations: {
      retry: 1
    }
  }
})

// Protected Route Component
interface ProtectedRouteProps {
  children: React.ReactNode
  requireAdmin?: boolean
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requireAdmin = false 
}) => {
  const { isAuthenticated, user } = useAuthStore()
  
  if (!isAuthenticated) {
    return <Navigate to="/auth" replace />
  }
  
  if (requireAdmin && user?.role !== 'admin') {
    return <Navigate to="/dashboard" replace />
  }
  
  return <>{children}</>
}

// Public Route Component (redirect if authenticated)
const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuthStore()
  
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }
  
  return <>{children}</>
}

// Loading Component with Mystical Theme
const AppLoading: React.FC = () => (
  <div className="min-h-screen bg-cosmic-blue flex items-center justify-center">
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.8 }}
      className="text-center"
    >
      <div className="relative">
        <LoadingSpinner size="large" variant="mystical" />
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5, duration: 0.6 }}
          className="mt-8 text-starlight text-lg font-medium"
        >
          Awakening the wheel...
        </motion.p>
      </div>
    </motion.div>
  </div>
)

// Error Fallback Component
const AppErrorFallback: React.FC<{ error: Error }> = ({ error }) => (
  <div className="min-h-screen bg-cosmic-blue flex items-center justify-center p-4">
    <div className="max-w-md w-full text-center">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-deep-purple/30 backdrop-blur-lg rounded-2xl p-8 border border-gold/20"
      >
        <div className="text-6xl mb-4">🌀</div>
        <h2 className="text-2xl font-bold text-gold mb-4">
          The Wheel Has Stumbled
        </h2>
        <p className="text-starlight mb-6">
          Something went wrong on this mystical journey. The wheel will turn again.
        </p>
        <button
          onClick={() => window.location.reload()}
          className="px-6 py-3 bg-gradient-to-r from-gold to-flame-orange text-cosmic-blue rounded-lg font-medium hover:scale-105 transition-transform"
        >
          Restart the Journey
        </button>
        {process.env.NODE_ENV === 'development' && (
          <details className="mt-4 text-left">
            <summary className="text-text-secondary cursor-pointer">
              Error Details
            </summary>
            <pre className="mt-2 text-xs text-red-400 bg-black/20 p-2 rounded overflow-auto">
              {error.message}
            </pre>
          </details>
        )}
      </motion.div>
    </div>
  </div>
)

// Main App Component
const App: React.FC = () => {
  const { theme } = useThemeStore()
  const { initializeAuth } = useAuthStore()
  const { initializeEncryption } = useEncryptionStore()
  const { isLoading, error } = useInitializeApp()

  // Initialize the application
  useEffect(() => {
    const initialize = async () => {
      try {
        // Initialize crypto system
        await initializeCrypto()
        
        // Initialize encryption store
        await initializeEncryption()
        
        // Initialize authentication
        await initializeAuth()
        
        console.log('🌟 Turning Wheel application initialized successfully')
      } catch (error) {
        console.error('❌ Failed to initialize application:', error)
      }
    }

    initialize()
  }, [initializeAuth, initializeEncryption])

  // Apply theme class to document
  useEffect(() => {
    document.documentElement.className = theme
  }, [theme])

  // Show loading state
  if (isLoading) {
    return <AppLoading />
  }

  // Show error state
  if (error) {
    return <AppErrorFallback error={error} />
  }

  return (
    <ErrorBoundary fallback={AppErrorFallback}>
      <HelmetProvider>
        <QueryClientProvider client={queryClient}>
          <Router>
            <div className={`app ${theme}`}>
              <AnimatePresence mode="wait">
                <Suspense fallback={<AppLoading />}>
                  <Routes>
                    {/* Public Routes */}
                    <Route 
                      path="/" 
                      element={
                        <PublicRoute>
                          <LandingPage />
                        </PublicRoute>
                      } 
                    />
                    <Route 
                      path="/auth" 
                      element={
                        <PublicRoute>
                          <AuthPage />
                        </PublicRoute>
                      } 
                    />
                    
                    {/* Protected Routes */}
                    <Route
                      path="/dashboard"
                      element={
                        <ProtectedRoute>
                          <Layout>
                            <DashboardPage />
                          </Layout>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/wheel"
                      element={
                        <ProtectedRoute>
                          <Layout>
                            <WheelPage />
                          </Layout>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/journey"
                      element={
                        <ProtectedRoute>
                          <Layout>
                            <JourneyPage />
                          </Layout>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/profile"
                      element={
                        <ProtectedRoute>
                          <Layout>
                            <ProfilePage />
                          </Layout>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/analytics"
                      element={
                        <ProtectedRoute requireAdmin>
                          <Layout>
                            <AnalyticsPage />
                          </Layout>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/settings"
                      element={
                        <ProtectedRoute>
                          <Layout>
                            <SettingsPage />
                          </Layout>
                        </ProtectedRoute>
                      }
                    />
                    
                    {/* Catch all - redirect to dashboard if authenticated, otherwise landing */}
                    <Route 
                      path="*" 
                      element={<Navigate to="/" replace />} 
                    />
                  </Routes>
                </Suspense>
              </AnimatePresence>
            </div>
          </Router>
          
          {/* Global Toast Notifications */}
          <Toaster
            position="top-right"
            toastOptions={{
              duration: 4000,
              style: {
                background: 'rgba(45, 27, 105, 0.95)',
                color: '#E6F3FF',
                border: '1px solid rgba(255, 215, 0, 0.2)',
                borderRadius: '12px',
                backdropFilter: 'blur(10px)',
              },
              success: {
                iconTheme: {
                  primary: '#FFD700',
                  secondary: 'rgba(45, 27, 105, 0.95)',
                },
              },
              error: {
                iconTheme: {
                  primary: '#FF6B35',
                  secondary: 'rgba(45, 27, 105, 0.95)',
                },
              },
            }}
          />
        </QueryClientProvider>
      </HelmetProvider>
    </ErrorBoundary>
  )
}

export default App
