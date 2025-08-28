/**
 * API Client with Authentication and Encryption Support
 * Handles HTTP requests, token management, and automatic encryption/decryption
 */

import axios, { 
  AxiosInstance, 
  AxiosRequestConfig, 
  AxiosResponse, 
  AxiosError,
  InternalAxiosRequestConfig
} from 'axios'
import toast from 'react-hot-toast'

// Crypto manager for encryption/decryption
import { cryptoManager } from '@crypto/cryptoManager'

// Types
export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  message?: string
  error?: string
  details?: any
}

export interface ApiError {
  message: string
  status: number
  code?: string
  details?: any
}

export interface RequestConfig extends AxiosRequestConfig {
  encrypt?: boolean
  decrypt?: boolean
  skipAuth?: boolean
  skipErrorToast?: boolean
}

class ApiClient {
  private instance: AxiosInstance
  private authToken: string | null = null
  private refreshPromise: Promise<string> | null = null

  constructor() {
    this.instance = axios.create({
      baseURL: import.meta.env.VITE_API_URL || '/api',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    this.setupInterceptors()
  }

  /**
   * Setup request and response interceptors
   */
  private setupInterceptors(): void {
    // Request interceptor
    this.instance.interceptors.request.use(
      async (config: InternalAxiosRequestConfig) => {
        // Add auth token if available and not explicitly skipped
        if (this.authToken && !config.skipAuth) {
          config.headers.Authorization = `Bearer ${this.authToken}`
        }

        // Add request ID for tracking
        config.headers['X-Request-ID'] = crypto.randomUUID()

        // Add timestamp
        config.headers['X-Request-Time'] = new Date().toISOString()

        // Encrypt request body if requested and crypto is ready
        if (config.encrypt && cryptoManager.hasUserKey && config.data) {
          try {
            const encryptedData = await cryptoManager.encryptString(
              typeof config.data === 'string' ? config.data : JSON.stringify(config.data)
            )
            config.data = { encrypted: encryptedData }
            config.headers['X-Encrypted'] = 'true'
          } catch (error) {
            console.error('Failed to encrypt request data:', error)
            throw new Error('Encryption failed')
          }
        }

        return config
      },
      (error) => {
        return Promise.reject(error)
      }
    )

    // Response interceptor
    this.instance.interceptors.response.use(
      async (response: AxiosResponse) => {
        // Decrypt response if it's encrypted
        if (response.config.decrypt && response.data?.encrypted) {
          try {
            const decryptedData = await cryptoManager.decryptString(response.data.encrypted)
            response.data = JSON.parse(decryptedData)
          } catch (error) {
            console.error('Failed to decrypt response data:', error)
            throw new Error('Decryption failed')
          }
        }

        return response
      },
      async (error: AxiosError) => {
        const originalRequest = error.config as RequestConfig & { _retry?: boolean }

        // Handle 401 errors (token expired)
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true

          try {
            // Try to refresh the token
            const newToken = await this.refreshToken()
            
            if (newToken && originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`
              return this.instance(originalRequest)
            }
          } catch (refreshError) {
            // Refresh failed, redirect to login
            this.handleAuthError()
            return Promise.reject(refreshError)
          }
        }

        // Handle other errors
        this.handleError(error, originalRequest)
        return Promise.reject(error)
      }
    )
  }

  /**
   * Set authentication token
   */
  setAuthToken(token: string): void {
    this.authToken = token
  }

  /**
   * Clear authentication token
   */
  clearAuthToken(): void {
    this.authToken = null
  }

  /**
   * Refresh authentication token
   */
  private async refreshToken(): Promise<string> {
    // Prevent multiple simultaneous refresh requests
    if (this.refreshPromise) {
      return this.refreshPromise
    }

    this.refreshPromise = new Promise(async (resolve, reject) => {
      try {
        // Get refresh token from localStorage or store
        const storedAuth = localStorage.getItem('turning-wheel-auth')
        if (!storedAuth) {
          throw new Error('No refresh token available')
        }

        const authData = JSON.parse(storedAuth)
        const refreshToken = authData.state?.tokens?.refreshToken

        if (!refreshToken) {
          throw new Error('No refresh token available')
        }

        // Make refresh request without interceptors
        const response = await axios.post(
          `${this.instance.defaults.baseURL}/auth/refresh`,
          { refreshToken },
          {
            headers: { 'Content-Type': 'application/json' }
          }
        )

        const { tokens } = response.data.data
        this.setAuthToken(tokens.accessToken)

        // Update stored tokens
        const updatedAuthData = {
          ...authData,
          state: {
            ...authData.state,
            tokens
          }
        }
        localStorage.setItem('turning-wheel-auth', JSON.stringify(updatedAuthData))

        resolve(tokens.accessToken)
      } catch (error) {
        reject(error)
      } finally {
        this.refreshPromise = null
      }
    })

    return this.refreshPromise
  }

  /**
   * Handle authentication errors
   */
  private handleAuthError(): void {
    // Clear stored auth data
    localStorage.removeItem('turning-wheel-auth')
    this.clearAuthToken()

    // Redirect to login (if not already there)
    if (!window.location.pathname.includes('/auth')) {
      toast.error('Session expired. Please log in again.')
      window.location.href = '/auth'
    }
  }

  /**
   * Handle API errors
   */
  private handleError(error: AxiosError, config?: RequestConfig): void {
    if (config?.skipErrorToast) {
      return
    }

    const response = error.response
    const message = response?.data?.message || response?.data?.error || error.message

    // Don't show toast for certain status codes
    const skipToastCodes = [401, 404]
    if (response && skipToastCodes.includes(response.status)) {
      return
    }

    // Show error toast
    toast.error(message || 'An unexpected error occurred')

    // Log error details in development
    if (import.meta.env.DEV) {
      console.error('API Error:', {
        url: error.config?.url,
        method: error.config?.method,
        status: response?.status,
        message: message,
        response: response?.data
      })
    }
  }

  /**
   * GET request
   */
  async get<T>(url: string, config?: RequestConfig): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.instance.get(url, config)
  }

  /**
   * POST request
   */
  async post<T>(url: string, data?: any, config?: RequestConfig): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.instance.post(url, data, config)
  }

  /**
   * PUT request
   */
  async put<T>(url: string, data?: any, config?: RequestConfig): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.instance.put(url, data, config)
  }

  /**
   * PATCH request
   */
  async patch<T>(url: string, data?: any, config?: RequestConfig): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.instance.patch(url, data, config)
  }

  /**
   * DELETE request
   */
  async delete<T>(url: string, config?: RequestConfig): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.instance.delete(url, config)
  }

  /**
   * Upload file with progress tracking
   */
  async uploadFile<T>(
    url: string,
    file: File,
    onProgress?: (progress: number) => void,
    config?: RequestConfig
  ): Promise<AxiosResponse<ApiResponse<T>>> {
    const formData = new FormData()
    formData.append('file', file)

    return this.instance.post(url, formData, {
      ...config,
      headers: {
        ...config?.headers,
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      },
    })
  }

  /**
   * Download file with progress tracking
   */
  async downloadFile(
    url: string,
    filename?: string,
    onProgress?: (progress: number) => void,
    config?: RequestConfig
  ): Promise<void> {
    const response = await this.instance.get(url, {
      ...config,
      responseType: 'blob',
      onDownloadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      },
    })

    // Create download link
    const blob = new Blob([response.data])
    const downloadUrl = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = downloadUrl
    link.download = filename || 'download'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(downloadUrl)
  }

  /**
   * Make encrypted request
   */
  async encryptedRequest<T>(
    method: 'get' | 'post' | 'put' | 'patch' | 'delete',
    url: string,
    data?: any,
    config?: RequestConfig
  ): Promise<AxiosResponse<ApiResponse<T>>> {
    const encryptedConfig: RequestConfig = {
      ...config,
      encrypt: method !== 'get',
      decrypt: true
    }

    switch (method) {
      case 'get':
        return this.get<T>(url, encryptedConfig)
      case 'post':
        return this.post<T>(url, data, encryptedConfig)
      case 'put':
        return this.put<T>(url, data, encryptedConfig)
      case 'patch':
        return this.patch<T>(url, data, encryptedConfig)
      case 'delete':
        return this.delete<T>(url, encryptedConfig)
      default:
        throw new Error(`Unsupported method: ${method}`)
    }
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.get('/health', { skipAuth: true, skipErrorToast: true })
      return response.data.success
    } catch {
      return false
    }
  }

  /**
   * Get current user
   */
  async getCurrentUser(): Promise<AxiosResponse<ApiResponse<any>>> {
    return this.get('/auth/me')
  }

  /**
   * Get instance for direct use
   */
  getInstance(): AxiosInstance {
    return this.instance
  }
}

// Create and export singleton instance
export const apiClient = new ApiClient()

// Export types and utilities
export { ApiClient }
export type { ApiResponse, ApiError, RequestConfig }

export default apiClient
