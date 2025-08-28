/**
 * WebCrypto End-to-End Encryption Manager
 * Provides client-side encryption using Web Crypto API
 */

import { Buffer } from 'buffer'

// Encryption Configuration
export const CRYPTO_CONFIG = {
  algorithms: {
    aes: 'AES-GCM',
    rsa: 'RSA-OAEP',
    pbkdf2: 'PBKDF2',
    hash: 'SHA-256'
  },
  keyLengths: {
    aes: 256,
    rsa: 2048,
    salt: 32,
    iv: 12,
    tag: 16
  },
  iterations: 100000
} as const

// Type definitions
export interface EncryptedData {
  encrypted: string
  iv: string
  tag?: string
  algorithm: string
  keyLength: number
}

export interface KeyPair {
  publicKey: CryptoKey
  privateKey: CryptoKey
  publicKeyPem?: string
  privateKeyPem?: string
}

export interface HybridEncryptedData {
  data: EncryptedData
  key: EncryptedData
  type: 'hybrid'
}

export interface UserKeyInfo {
  salt: string
  iterations: number
  algorithm: string
  derivedKey?: CryptoKey
}

// Crypto Manager Class
export class CryptoManager {
  private static instance: CryptoManager
  private isInitialized = false
  private userKey: CryptoKey | null = null
  private keyPair: KeyPair | null = null

  private constructor() {}

  static getInstance(): CryptoManager {
    if (!CryptoManager.instance) {
      CryptoManager.instance = new CryptoManager()
    }
    return CryptoManager.instance
  }

  /**
   * Initialize the crypto system
   */
  async initialize(): Promise<void> {
    try {
      // Check WebCrypto availability
      if (!window.crypto || !window.crypto.subtle) {
        throw new Error('WebCrypto API not available')
      }

      // Test basic functionality
      await this.testCryptoSupport()
      
      this.isInitialized = true
      console.log('🔒 Crypto Manager initialized successfully')
    } catch (error) {
      console.error('❌ Failed to initialize crypto manager:', error)
      throw error
    }
  }

  /**
   * Test crypto support
   */
  private async testCryptoSupport(): Promise<void> {
    try {
      // Test AES-GCM
      const testKey = await window.crypto.subtle.generateKey(
        {
          name: CRYPTO_CONFIG.algorithms.aes,
          length: CRYPTO_CONFIG.keyLengths.aes
        },
        false,
        ['encrypt', 'decrypt']
      )

      const testData = new TextEncoder().encode('test')
      const iv = window.crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.keyLengths.iv))
      
      const encrypted = await window.crypto.subtle.encrypt(
        { name: CRYPTO_CONFIG.algorithms.aes, iv },
        testKey,
        testData
      )

      await window.crypto.subtle.decrypt(
        { name: CRYPTO_CONFIG.algorithms.aes, iv },
        testKey,
        encrypted
      )

      // Test RSA-OAEP
      await window.crypto.subtle.generateKey(
        {
          name: CRYPTO_CONFIG.algorithms.rsa,
          modulusLength: CRYPTO_CONFIG.keyLengths.rsa,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: CRYPTO_CONFIG.algorithms.hash
        },
        false,
        ['encrypt', 'decrypt']
      )

      console.log('✅ Crypto support test passed')
    } catch (error) {
      throw new Error(`Crypto support test failed: ${error}`)
    }
  }

  /**
   * Generate random bytes
   */
  generateRandomBytes(length: number): Uint8Array {
    return window.crypto.getRandomValues(new Uint8Array(length))
  }

  /**
   * Generate salt for key derivation
   */
  generateSalt(): Uint8Array {
    return this.generateRandomBytes(CRYPTO_CONFIG.keyLengths.salt)
  }

  /**
   * Derive key from password using PBKDF2
   */
  async deriveKeyFromPassword(
    password: string,
    salt: Uint8Array,
    iterations: number = CRYPTO_CONFIG.iterations
  ): Promise<CryptoKey> {
    try {
      const passwordBuffer = new TextEncoder().encode(password)
      
      const baseKey = await window.crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        CRYPTO_CONFIG.algorithms.pbkdf2,
        false,
        ['deriveKey']
      )

      const derivedKey = await window.crypto.subtle.deriveKey(
        {
          name: CRYPTO_CONFIG.algorithms.pbkdf2,
          salt,
          iterations,
          hash: CRYPTO_CONFIG.algorithms.hash
        },
        baseKey,
        {
          name: CRYPTO_CONFIG.algorithms.aes,
          length: CRYPTO_CONFIG.keyLengths.aes
        },
        false,
        ['encrypt', 'decrypt']
      )

      return derivedKey
    } catch (error) {
      throw new Error(`Key derivation failed: ${error}`)
    }
  }

  /**
   * Set user encryption key
   */
  async setUserKey(password: string, keyInfo: UserKeyInfo): Promise<void> {
    try {
      const salt = this.base64ToUint8Array(keyInfo.salt)
      this.userKey = await this.deriveKeyFromPassword(password, salt, keyInfo.iterations)
      console.log('🔑 User encryption key set successfully')
    } catch (error) {
      throw new Error(`Failed to set user key: ${error}`)
    }
  }

  /**
   * Generate AES key
   */
  async generateAESKey(): Promise<CryptoKey> {
    return await window.crypto.subtle.generateKey(
      {
        name: CRYPTO_CONFIG.algorithms.aes,
        length: CRYPTO_CONFIG.keyLengths.aes
      },
      true,
      ['encrypt', 'decrypt']
    )
  }

  /**
   * Generate RSA key pair
   */
  async generateRSAKeyPair(): Promise<KeyPair> {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: CRYPTO_CONFIG.algorithms.rsa,
          modulusLength: CRYPTO_CONFIG.keyLengths.rsa,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: CRYPTO_CONFIG.algorithms.hash
        },
        true,
        ['encrypt', 'decrypt']
      )

      // Export keys to PEM format for storage/transmission
      const publicKeyPem = await this.exportPublicKeyToPem(keyPair.publicKey)
      const privateKeyPem = await this.exportPrivateKeyToPem(keyPair.privateKey)

      this.keyPair = {
        ...keyPair,
        publicKeyPem,
        privateKeyPem
      }

      return this.keyPair
    } catch (error) {
      throw new Error(`RSA key pair generation failed: ${error}`)
    }
  }

  /**
   * Encrypt data with AES-GCM
   */
  async encryptAES(data: string | Uint8Array, key?: CryptoKey): Promise<EncryptedData> {
    try {
      const encryptionKey = key || this.userKey
      if (!encryptionKey) {
        throw new Error('No encryption key available')
      }

      const dataBuffer = typeof data === 'string' 
        ? new TextEncoder().encode(data)
        : data

      const iv = this.generateRandomBytes(CRYPTO_CONFIG.keyLengths.iv)
      
      const encrypted = await window.crypto.subtle.encrypt(
        {
          name: CRYPTO_CONFIG.algorithms.aes,
          iv
        },
        encryptionKey,
        dataBuffer
      )

      return {
        encrypted: this.arrayBufferToBase64(encrypted),
        iv: this.uint8ArrayToBase64(iv),
        algorithm: CRYPTO_CONFIG.algorithms.aes,
        keyLength: CRYPTO_CONFIG.keyLengths.aes
      }
    } catch (error) {
      throw new Error(`AES encryption failed: ${error}`)
    }
  }

  /**
   * Decrypt data with AES-GCM
   */
  async decryptAES(encryptedData: EncryptedData, key?: CryptoKey): Promise<Uint8Array> {
    try {
      const decryptionKey = key || this.userKey
      if (!decryptionKey) {
        throw new Error('No decryption key available')
      }

      const encrypted = this.base64ToArrayBuffer(encryptedData.encrypted)
      const iv = this.base64ToUint8Array(encryptedData.iv)

      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: encryptedData.algorithm,
          iv
        },
        decryptionKey,
        encrypted
      )

      return new Uint8Array(decrypted)
    } catch (error) {
      throw new Error(`AES decryption failed: ${error}`)
    }
  }

  /**
   * Encrypt string and return as string
   */
  async encryptString(plaintext: string, key?: CryptoKey): Promise<string> {
    const encrypted = await this.encryptAES(plaintext, key)
    return JSON.stringify(encrypted)
  }

  /**
   * Decrypt string from encrypted string
   */
  async decryptString(encryptedString: string, key?: CryptoKey): Promise<string> {
    try {
      const encryptedData = JSON.parse(encryptedString) as EncryptedData
      const decrypted = await this.decryptAES(encryptedData, key)
      return new TextDecoder().decode(decrypted)
    } catch (error) {
      throw new Error(`String decryption failed: ${error}`)
    }
  }

  /**
   * Encrypt object (JSON serialization + AES)
   */
  async encryptObject(obj: any, key?: CryptoKey): Promise<EncryptedData> {
    const jsonString = JSON.stringify(obj)
    return await this.encryptAES(jsonString, key)
  }

  /**
   * Decrypt object (AES + JSON deserialization)
   */
  async decryptObject<T>(encryptedData: EncryptedData, key?: CryptoKey): Promise<T> {
    const decrypted = await this.decryptAES(encryptedData, key)
    const jsonString = new TextDecoder().decode(decrypted)
    return JSON.parse(jsonString) as T
  }

  /**
   * Hybrid encryption: encrypt data with random AES key, then encrypt AES key with RSA
   */
  async hybridEncrypt(data: string, publicKey: CryptoKey): Promise<HybridEncryptedData> {
    try {
      // Generate random AES key
      const dataKey = await this.generateAESKey()
      
      // Encrypt data with AES key
      const encryptedData = await this.encryptAES(data, dataKey)
      
      // Export AES key as raw bytes
      const keyBytes = await window.crypto.subtle.exportKey('raw', dataKey)
      
      // Encrypt AES key with RSA public key
      const encryptedKey = await window.crypto.subtle.encrypt(
        { name: CRYPTO_CONFIG.algorithms.rsa },
        publicKey,
        keyBytes
      )

      return {
        data: encryptedData,
        key: {
          encrypted: this.arrayBufferToBase64(encryptedKey),
          iv: '', // RSA doesn't use IV
          algorithm: CRYPTO_CONFIG.algorithms.rsa,
          keyLength: CRYPTO_CONFIG.keyLengths.rsa
        },
        type: 'hybrid'
      }
    } catch (error) {
      throw new Error(`Hybrid encryption failed: ${error}`)
    }
  }

  /**
   * Hybrid decryption: decrypt AES key with RSA, then decrypt data with AES key
   */
  async hybridDecrypt(encryptedHybrid: HybridEncryptedData, privateKey: CryptoKey): Promise<string> {
    try {
      // Decrypt AES key with RSA private key
      const encryptedKeyBytes = this.base64ToArrayBuffer(encryptedHybrid.key.encrypted)
      const keyBytes = await window.crypto.subtle.decrypt(
        { name: CRYPTO_CONFIG.algorithms.rsa },
        privateKey,
        encryptedKeyBytes
      )

      // Import the AES key
      const dataKey = await window.crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: CRYPTO_CONFIG.algorithms.aes },
        false,
        ['decrypt']
      )

      // Decrypt the data
      const decrypted = await this.decryptAES(encryptedHybrid.data, dataKey)
      return new TextDecoder().decode(decrypted)
    } catch (error) {
      throw new Error(`Hybrid decryption failed: ${error}`)
    }
  }

  /**
   * Generate secure hash
   */
  async hash(data: string): Promise<string> {
    const dataBuffer = new TextEncoder().encode(data)
    const hashBuffer = await window.crypto.subtle.digest(CRYPTO_CONFIG.algorithms.hash, dataBuffer)
    return this.arrayBufferToBase64(hashBuffer)
  }

  /**
   * Generate HMAC
   */
  async generateHMAC(data: string, key: CryptoKey): Promise<string> {
    const dataBuffer = new TextEncoder().encode(data)
    const signature = await window.crypto.subtle.sign('HMAC', key, dataBuffer)
    return this.arrayBufferToBase64(signature)
  }

  /**
   * Export public key to PEM format
   */
  private async exportPublicKeyToPem(publicKey: CryptoKey): Promise<string> {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey)
    const base64 = this.arrayBufferToBase64(exported)
    return `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----`
  }

  /**
   * Export private key to PEM format
   */
  private async exportPrivateKeyToPem(privateKey: CryptoKey): Promise<string> {
    const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey)
    const base64 = this.arrayBufferToBase64(exported)
    return `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----`
  }

  /**
   * Import public key from PEM format
   */
  async importPublicKeyFromPem(pem: string): Promise<CryptoKey> {
    const base64 = pem
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/\s/g, '')
    
    const keyData = this.base64ToArrayBuffer(base64)
    
    return await window.crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: CRYPTO_CONFIG.algorithms.rsa,
        hash: CRYPTO_CONFIG.algorithms.hash
      },
      false,
      ['encrypt']
    )
  }

  /**
   * Import private key from PEM format
   */
  async importPrivateKeyFromPem(pem: string): Promise<CryptoKey> {
    const base64 = pem
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\s/g, '')
    
    const keyData = this.base64ToArrayBuffer(base64)
    
    return await window.crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: CRYPTO_CONFIG.algorithms.rsa,
        hash: CRYPTO_CONFIG.algorithms.hash
      },
      false,
      ['decrypt']
    )
  }

  // Utility functions for encoding/decoding
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes.buffer
  }

  private uint8ArrayToBase64(uint8Array: Uint8Array): string {
    return this.arrayBufferToBase64(uint8Array.buffer)
  }

  private base64ToUint8Array(base64: string): Uint8Array {
    return new Uint8Array(this.base64ToArrayBuffer(base64))
  }

  // Getters
  get isReady(): boolean {
    return this.isInitialized
  }

  get hasUserKey(): boolean {
    return this.userKey !== null
  }

  get hasKeyPair(): boolean {
    return this.keyPair !== null
  }

  get publicKeyPem(): string | undefined {
    return this.keyPair?.publicKeyPem
  }
}

// Export singleton instance
export const cryptoManager = CryptoManager.getInstance()

// Initialization function
export async function initializeCrypto(): Promise<void> {
  await cryptoManager.initialize()
}

// Utility functions
export function generateUserKeyInfo(password: string): Promise<UserKeyInfo> {
  return new Promise((resolve) => {
    const salt = cryptoManager.generateSalt()
    resolve({
      salt: cryptoManager['uint8ArrayToBase64'](salt),
      iterations: CRYPTO_CONFIG.iterations,
      algorithm: CRYPTO_CONFIG.algorithms.aes
    })
  })
}

export default cryptoManager
