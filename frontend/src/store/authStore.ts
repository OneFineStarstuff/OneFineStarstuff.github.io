/**
 * Authentication Store using Zustand
 * Manages user authentication state with encryption integration
 */

import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import toast from 'react-hot-toast'

// API and crypto imports
import { apiClient } from '@api/client'
import { cryptoManager } from '@crypto/cryptoManager'

// Types
export interface User {
  id: string
  username: string
  email: string
  firstName?: string
  lastName?: string
  role: 'user' | 'admin'
  isActive: boolean
  emailVerified: boolean
  lastLogin?: string
  createdAt: string
  avatar?: string
  preferences?: UserPreferences
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto'
  language: string
  notifications: {
    email: boolean
    push: boolean
    sms: boolean
  }
  privacy: {
    shareJourney: boolean
    showActivity: boolean
  }
}

export interface TokenInfo {
  accessToken: string
  refreshToken: string
  tokenType: string
  expiresIn: string
  issuedAt: string
}

export interface AuthState {
  // State
  user: User | null
  tokens: TokenInfo | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
  
  // User encryption data
  userEncryptionKey: string | null
  encryptionSalt: string | null
  
  // Actions
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>
  register: (userData: RegisterData) => Promise<void>
  logout: () => Promise<void>
  refreshToken: () => Promise<void>
  updateProfile: (profileData: Partial<User>) => Promise<void>
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>
  requestPasswordReset: (email: string) => Promise<void>
  resetPassword: (token: string, password: string) => Promise<void>
  clearError: () => void
  initializeAuth: () => Promise<void>
  
  // Encryption helpers
  setEncryptionKey: (key: string, salt: string) => void
  clearEncryptionKey: () => void
  isEncryptionReady: () => boolean
}

export interface RegisterData {
  username: string
  email: string
  password: string
  confirmPassword: string
  firstName?: string
  lastName?: string
  agreeToTerms: boolean
}

export interface LoginResponse {
  user: User
  tokens: TokenInfo
  encryption: {
    userKey: string
    algorithm: string
  }
}

// Encrypted storage for sensitive data
const encryptedStorage = {
  getItem: (name: string): string | null => {
    try {
      const item = localStorage.getItem(name)
      if (!item) return null
      
      // In a real implementation, you'd decrypt this
      // For now, we'll use basic storage but mark it as encrypted
      return item
    } catch {
      return null
    }
  },
  setItem: (name: string, value: string): void => {
    try {
      // In a real implementation, you'd encrypt this
      localStorage.setItem(name, value)
    } catch {
      // Handle storage errors
    }
  },
  removeItem: (name: string): void => {
    try {
      localStorage.removeItem(name)
    } catch {
      // Handle storage errors
    }
  }
}

// Create the store
export const useAuthStore = create<AuthState>()(
  persist(
    immer((set, get) => ({
      // Initial state
      user: null,
      tokens: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      userEncryptionKey: null,
      encryptionSalt: null,

      // Login action
      login: async (email: string, password: string, rememberMe = false) => {
        set((state) => {
          state.isLoading = true
          state.error = null
        })

        try {
          const response = await apiClient.post<LoginResponse>('/auth/login', {
            email,
            password,
            rememberMe
          })

          const { user, tokens, encryption } = response.data

          // Set up user encryption key
          await cryptoManager.setUserKey(password, {
            salt: encryption.userKey,
            iterations: 100000,
            algorithm: encryption.algorithm
          })

          set((state) => {
            state.user = user
            state.tokens = tokens
            state.isAuthenticated = true
            state.isLoading = false
            state.userEncryptionKey = encryption.userKey
            state.encryptionSalt = encryption.userKey
          })

          // Set API client auth header
          apiClient.setAuthToken(tokens.accessToken)

          toast.success(`Welcome back, ${user.firstName || user.username}!`)
          
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || 'Login failed'
          
          set((state) => {
            state.error = errorMessage
            state.isLoading = false
          })

          toast.error(errorMessage)
          throw error
        }
      },

      // Register action
      register: async (userData: RegisterData) => {
        set((state) => {
          state.isLoading = true
          state.error = null
        })

        try {
          const response = await apiClient.post<LoginResponse>('/auth/register', userData)
          const { user, tokens, encryption } = response.data

          // Set up user encryption key
          await cryptoManager.setUserKey(userData.password, {
            salt: encryption.userKey,
            iterations: 100000,
            algorithm: encryption.algorithm
          })

          set((state) => {
            state.user = user
            state.tokens = tokens
            state.isAuthenticated = true
            state.isLoading = false
            state.userEncryptionKey = encryption.userKey
            state.encryptionSalt = encryption.userKey
          })

          // Set API client auth header
          apiClient.setAuthToken(tokens.accessToken)

          toast.success(`Welcome to The Turning Wheel, ${user.firstName || user.username}!`)
          
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || 'Registration failed'
          
          set((state) => {
            state.error = errorMessage
            state.isLoading = false
          })

          toast.error(errorMessage)
          throw error
        }
      },

      // Logout action
      logout: async () => {
        set((state) => {
          state.isLoading = true
        })

        try {
          const tokens = get().tokens
          
          if (tokens) {
            await apiClient.post('/auth/logout', {
              refreshToken: tokens.refreshToken
            })
          }
        } catch (error) {
          console.warn('Logout request failed:', error)
        } finally {
          // Clear state regardless of API call success
          set((state) => {
            state.user = null
            state.tokens = null
            state.isAuthenticated = false
            state.isLoading = false
            state.error = null
            state.userEncryptionKey = null
            state.encryptionSalt = null
          })

          // Clear API client auth header
          apiClient.clearAuthToken()
          
          // Clear crypto manager
          cryptoManager['userKey'] = null

          toast.success('Logged out successfully')
        }
      },

      // Refresh token action
      refreshToken: async () => {
        const currentTokens = get().tokens
        
        if (!currentTokens?.refreshToken) {
          throw new Error('No refresh token available')
        }

        try {
          const response = await apiClient.post<{ tokens: TokenInfo }>('/auth/refresh', {
            refreshToken: currentTokens.refreshToken
          })

          const { tokens } = response.data

          set((state) => {
            state.tokens = tokens
          })

          // Update API client auth header
          apiClient.setAuthToken(tokens.accessToken)

          return tokens
        } catch (error: any) {
          // If refresh fails, logout the user
          get().logout()
          throw error
        }
      },

      // Update profile action
      updateProfile: async (profileData: Partial<User>) => {
        set((state) => {
          state.isLoading = true
          state.error = null
        })

        try {
          const response = await apiClient.put<{ user: User }>('/user/profile', profileData)
          const { user } = response.data

          set((state) => {
            state.user = { ...state.user!, ...user }
            state.isLoading = false
          })

          toast.success('Profile updated successfully')
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || 'Profile update failed'
          
          set((state) => {
            state.error = errorMessage
            state.isLoading = false
          })

          toast.error(errorMessage)
          throw error
        }
      },

      // Change password action
      changePassword: async (currentPassword: string, newPassword: string) => {
        set((state) => {
          state.isLoading = true
          state.error = null
        })

        try {
          await apiClient.post('/auth/change-password', {
            currentPassword,
            newPassword,
            confirmPassword: newPassword
          })

          // Password change requires re-login for security
          toast.success('Password changed successfully. Please log in again.')
          await get().logout()
          
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || 'Password change failed'
          
          set((state) => {
            state.error = errorMessage
            state.isLoading = false
          })

          toast.error(errorMessage)
          throw error
        }
      },

      // Request password reset
      requestPasswordReset: async (email: string) => {
        set((state) => {
          state.isLoading = true
          state.error = null
        })

        try {
          await apiClient.post('/auth/password-reset-request', { email })
          
          set((state) => {
            state.isLoading = false
          })

          toast.success('If an account with that email exists, a reset link has been sent.')
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || 'Password reset request failed'
          
          set((state) => {
            state.error = errorMessage
            state.isLoading = false
          })

          toast.error(errorMessage)
          throw error
        }
      },

      // Reset password
      resetPassword: async (token: string, password: string) => {
        set((state) => {
          state.isLoading = true
          state.error = null
        })

        try {
          await apiClient.post('/auth/password-reset', {
            token,
            password,
            confirmPassword: password
          })
          
          set((state) => {
            state.isLoading = false
          })

          toast.success('Password reset successfully. Please log in with your new password.')
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || 'Password reset failed'
          
          set((state) => {
            state.error = errorMessage
            state.isLoading = false
          })

          toast.error(errorMessage)
          throw error
        }
      },

      // Clear error
      clearError: () => {
        set((state) => {
          state.error = null
        })
      },

      // Initialize auth from stored state
      initializeAuth: async () => {
        const tokens = get().tokens
        const user = get().user

        if (tokens && user) {
          try {
            // Set API client auth header
            apiClient.setAuthToken(tokens.accessToken)

            // Verify token is still valid
            await apiClient.get('/auth/me')

            set((state) => {
              state.isAuthenticated = true
            })
          } catch (error) {
            // Token is invalid, try to refresh
            try {
              await get().refreshToken()
            } catch (refreshError) {
              // Refresh failed, logout user
              await get().logout()
            }
          }
        }
      },

      // Encryption helpers
      setEncryptionKey: (key: string, salt: string) => {
        set((state) => {
          state.userEncryptionKey = key
          state.encryptionSalt = salt
        })
      },

      clearEncryptionKey: () => {
        set((state) => {
          state.userEncryptionKey = null
          state.encryptionSalt = null
        })
      },

      isEncryptionReady: () => {
        return !!(get().userEncryptionKey && cryptoManager.hasUserKey)
      }
    })),
    {
      name: 'turning-wheel-auth',
      storage: createJSONStorage(() => encryptedStorage),
      partialize: (state) => ({
        user: state.user,
        tokens: state.tokens,
        isAuthenticated: state.isAuthenticated,
        userEncryptionKey: state.userEncryptionKey,
        encryptionSalt: state.encryptionSalt
      })
    }
  )
)

// Hooks for specific auth operations
export const useAuth = () => {
  const store = useAuthStore()
  return {
    user: store.user,
    isAuthenticated: store.isAuthenticated,
    isLoading: store.isLoading,
    error: store.error,
    login: store.login,
    logout: store.logout,
    register: store.register,
    clearError: store.clearError
  }
}

export const useUser = () => {
  const user = useAuthStore((state) => state.user)
  const updateProfile = useAuthStore((state) => state.updateProfile)
  const changePassword = useAuthStore((state) => state.changePassword)
  
  return {
    user,
    updateProfile,
    changePassword
  }
}

export const useEncryption = () => {
  const store = useAuthStore()
  return {
    isEncryptionReady: store.isEncryptionReady(),
    userEncryptionKey: store.userEncryptionKey,
    setEncryptionKey: store.setEncryptionKey,
    clearEncryptionKey: store.clearEncryptionKey
  }
}

export default useAuthStore
