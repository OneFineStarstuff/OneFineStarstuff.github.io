/**
 * AES-GCM Encryption Utilities
 * Provides end-to-end encryption capabilities for sensitive data
 */

import crypto from 'crypto';
import logger from './logger.js';

// Encryption configuration
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12; // 96 bits for GCM
const TAG_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32; // 256 bits for key derivation

// Master encryption key from environment
const MASTER_KEY = process.env.MASTER_ENCRYPTION_KEY 
  ? Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'base64')
  : crypto.randomBytes(KEY_LENGTH);

if (!process.env.MASTER_ENCRYPTION_KEY) {
  logger.warn('No MASTER_ENCRYPTION_KEY found in environment. Using randomly generated key.');
  logger.warn('Generated key (base64):', MASTER_KEY.toString('base64'));
}

/**
 * Generate a cryptographically secure random key
 */
export function generateKey() {
  return crypto.randomBytes(KEY_LENGTH);
}

/**
 * Derive key from password using PBKDF2
 */
export function deriveKey(password, salt, iterations = 100000) {
  if (typeof password === 'string') {
    password = Buffer.from(password, 'utf8');
  }
  
  return crypto.pbkdf2Sync(password, salt, iterations, KEY_LENGTH, 'sha256');
}

/**
 * Generate salt for key derivation
 */
export function generateSalt() {
  return crypto.randomBytes(SALT_LENGTH);
}

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(plaintext, key = MASTER_KEY, additionalData = null) {
  try {
    // Convert string to buffer if needed
    const plaintextBuffer = typeof plaintext === 'string' 
      ? Buffer.from(plaintext, 'utf8') 
      : plaintext;
    
    // Generate random IV
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // Create cipher
    const cipher = crypto.createCipher(ALGORITHM, key, { authTagLength: TAG_LENGTH });
    cipher.setAutoPadding(false);
    
    // Set IV
    const cipherGcm = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // Add additional authenticated data if provided
    if (additionalData) {
      cipherGcm.setAAD(Buffer.from(additionalData, 'utf8'));
    }
    
    // Encrypt the data
    const encrypted = Buffer.concat([
      cipherGcm.update(plaintextBuffer),
      cipherGcm.final()
    ]);
    
    // Get authentication tag
    const authTag = cipherGcm.getAuthTag();
    
    // Return encrypted data with metadata
    return {
      encrypted: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      algorithm: ALGORITHM,
      keyLength: KEY_LENGTH,
      additionalData: additionalData || null
    };
  } catch (error) {
    logger.error('Encryption failed:', error);
    throw new Error('Encryption failed: ' + error.message);
  }
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(encryptedData, key = MASTER_KEY) {
  try {
    const {
      encrypted,
      iv,
      authTag,
      algorithm,
      additionalData
    } = encryptedData;
    
    // Validate algorithm
    if (algorithm !== ALGORITHM) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    // Convert from base64
    const encryptedBuffer = Buffer.from(encrypted, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64');
    const authTagBuffer = Buffer.from(authTag, 'base64');
    
    // Create decipher
    const decipher = crypto.createDecipheriv(algorithm, key, ivBuffer);
    
    // Set authentication tag
    decipher.setAuthTag(authTagBuffer);
    
    // Add additional authenticated data if it was used
    if (additionalData) {
      decipher.setAAD(Buffer.from(additionalData, 'utf8'));
    }
    
    // Decrypt the data
    const decrypted = Buffer.concat([
      decipher.update(encryptedBuffer),
      decipher.final()
    ]);
    
    return decrypted;
  } catch (error) {
    logger.error('Decryption failed:', error);
    throw new Error('Decryption failed: ' + error.message);
  }
}

/**
 * Encrypt string and return as string
 */
export function encryptString(plaintext, key = MASTER_KEY, additionalData = null) {
  const encrypted = encrypt(plaintext, key, additionalData);
  return JSON.stringify(encrypted);
}

/**
 * Decrypt string from encrypted string
 */
export function decryptString(encryptedString, key = MASTER_KEY) {
  try {
    const encryptedData = JSON.parse(encryptedString);
    const decrypted = decrypt(encryptedData, key);
    return decrypted.toString('utf8');
  } catch (error) {
    logger.error('String decryption failed:', error);
    throw new Error('String decryption failed: ' + error.message);
  }
}

/**
 * Encrypt object (serializes to JSON first)
 */
export function encryptObject(obj, key = MASTER_KEY, additionalData = null) {
  try {
    const jsonString = JSON.stringify(obj);
    return encrypt(jsonString, key, additionalData);
  } catch (error) {
    logger.error('Object encryption failed:', error);
    throw new Error('Object encryption failed: ' + error.message);
  }
}

/**
 * Decrypt object (deserializes from JSON)
 */
export function decryptObject(encryptedData, key = MASTER_KEY) {
  try {
    const decrypted = decrypt(encryptedData, key);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (error) {
    logger.error('Object decryption failed:', error);
    throw new Error('Object decryption failed: ' + error.message);
  }
}

/**
 * Generate encryption key pair for users
 */
export function generateUserKeyPair(password, userSalt = null) {
  const salt = userSalt || generateSalt();
  const key = deriveKey(password, salt);
  
  return {
    key: key.toString('base64'),
    salt: salt.toString('base64'),
    algorithm: ALGORITHM,
    iterations: 100000
  };
}

/**
 * Hybrid encryption: encrypt data with random key, then encrypt key with user key
 */
export function hybridEncrypt(plaintext, userKey, additionalData = null) {
  try {
    // Generate random data encryption key
    const dataKey = generateKey();
    
    // Encrypt the data with the random key
    const encryptedData = encrypt(plaintext, dataKey, additionalData);
    
    // Encrypt the data key with the user key
    const encryptedDataKey = encrypt(dataKey, userKey);
    
    return {
      data: encryptedData,
      key: encryptedDataKey,
      type: 'hybrid'
    };
  } catch (error) {
    logger.error('Hybrid encryption failed:', error);
    throw new Error('Hybrid encryption failed: ' + error.message);
  }
}

/**
 * Hybrid decryption: decrypt key first, then decrypt data
 */
export function hybridDecrypt(encryptedHybrid, userKey) {
  try {
    const { data, key } = encryptedHybrid;
    
    // Decrypt the data key
    const dataKey = decrypt(key, userKey);
    
    // Decrypt the data with the recovered key
    const decryptedData = decrypt(data, dataKey);
    
    return decryptedData;
  } catch (error) {
    logger.error('Hybrid decryption failed:', error);
    throw new Error('Hybrid decryption failed: ' + error.message);
  }
}

/**
 * Secure hash using SHA-256
 */
export function hash(data, salt = null) {
  const hash = crypto.createHash('sha256');
  
  if (salt) {
    hash.update(salt);
  }
  
  hash.update(typeof data === 'string' ? data : JSON.stringify(data));
  return hash.digest('hex');
}

/**
 * Generate HMAC signature
 */
export function generateHMAC(data, secret = MASTER_KEY) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(typeof data === 'string' ? data : JSON.stringify(data));
  return hmac.digest('hex');
}

/**
 * Verify HMAC signature
 */
export function verifyHMAC(data, signature, secret = MASTER_KEY) {
  const expectedSignature = generateHMAC(data, secret);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}

/**
 * Encrypt field for database storage
 */
export function encryptField(value, key = MASTER_KEY) {
  if (value === null || value === undefined) {
    return null;
  }
  
  try {
    const encrypted = encrypt(String(value), key);
    return {
      encrypted: encrypted.encrypted,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      algorithm: encrypted.algorithm
    };
  } catch (error) {
    logger.error('Field encryption failed:', error);
    throw new Error('Field encryption failed: ' + error.message);
  }
}

/**
 * Decrypt field from database
 */
export function decryptField(encryptedField, key = MASTER_KEY) {
  if (!encryptedField) {
    return null;
  }
  
  try {
    const decrypted = decrypt(encryptedField, key);
    return decrypted.toString('utf8');
  } catch (error) {
    logger.error('Field decryption failed:', error);
    throw new Error('Field decryption failed: ' + error.message);
  }
}

/**
 * Generate secure random token
 */
export function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate cryptographically secure UUID
 */
export function generateSecureUUID() {
  return crypto.randomUUID();
}

/**
 * Constant-time string comparison
 */
export function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  
  if (a.length !== b.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(
    Buffer.from(a, 'utf8'),
    Buffer.from(b, 'utf8')
  );
}

/**
 * Encrypt multiple fields for batch operations
 */
export function encryptFields(fields, key = MASTER_KEY) {
  const encrypted = {};
  
  for (const [fieldName, value] of Object.entries(fields)) {
    encrypted[fieldName] = encryptField(value, key);
  }
  
  return encrypted;
}

/**
 * Decrypt multiple fields for batch operations
 */
export function decryptFields(encryptedFields, key = MASTER_KEY) {
  const decrypted = {};
  
  for (const [fieldName, encryptedValue] of Object.entries(encryptedFields)) {
    decrypted[fieldName] = decryptField(encryptedValue, key);
  }
  
  return decrypted;
}

/**
 * Key rotation utility
 */
export function rotateEncryption(encryptedData, oldKey, newKey) {
  try {
    // Decrypt with old key
    const plaintext = decrypt(encryptedData, oldKey);
    
    // Re-encrypt with new key
    return encrypt(plaintext, newKey, encryptedData.additionalData);
  } catch (error) {
    logger.error('Key rotation failed:', error);
    throw new Error('Key rotation failed: ' + error.message);
  }
}

/**
 * Validate encryption configuration
 */
export function validateConfig() {
  return {
    algorithm: ALGORITHM,
    keyLength: KEY_LENGTH,
    ivLength: IV_LENGTH,
    tagLength: TAG_LENGTH,
    saltLength: SALT_LENGTH,
    masterKeyPresent: !!process.env.MASTER_ENCRYPTION_KEY,
    isSecure: MASTER_KEY.length === KEY_LENGTH
  };
}

export default {
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  encryptObject,
  decryptObject,
  encryptField,
  decryptField,
  encryptFields,
  decryptFields,
  hybridEncrypt,
  hybridDecrypt,
  generateKey,
  deriveKey,
  generateSalt,
  generateUserKeyPair,
  hash,
  generateHMAC,
  verifyHMAC,
  generateSecureToken,
  generateSecureUUID,
  safeCompare,
  rotateEncryption,
  validateConfig
};
