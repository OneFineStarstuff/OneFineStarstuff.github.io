/**
 * Environment and Input Validation Utilities
 * Validates configuration and user inputs for security
 */

import Joi from 'joi';
import logger from './logger.js';

/**
 * Environment variable schema
 */
const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'staging', 'production').default('development'),
  PORT: Joi.number().port().default(8080),
  
  // Database
  DATABASE_URL: Joi.string().uri().optional(),
  DB_HOST: Joi.string().hostname().optional(),
  DB_PORT: Joi.number().port().default(5432),
  DB_NAME: Joi.string().alphanum().optional(),
  DB_USER: Joi.string().optional(),
  DB_PASSWORD: Joi.string().optional(),
  
  // Redis
  REDIS_URL: Joi.string().uri().optional(),
  REDIS_HOST: Joi.string().hostname().optional(),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional(),
  
  // JWT Configuration
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRY: Joi.string().default('15m'),
  JWT_REFRESH_EXPIRY: Joi.string().default('7d'),
  
  // Encryption
  MASTER_ENCRYPTION_KEY: Joi.string().base64().optional(),
  
  // External Services
  FRONTEND_URL: Joi.string().uri().default('http://localhost:3000'),
  
  // Email
  SMTP_HOST: Joi.string().hostname().optional(),
  SMTP_PORT: Joi.number().port().optional(),
  SMTP_USER: Joi.string().email().optional(),
  SMTP_PASSWORD: Joi.string().optional(),
  
  // Logging
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
  LOG_DIR: Joi.string().optional(),
  
  // Security
  RATE_LIMIT_MAX: Joi.number().integer().min(1).default(100),
  RATE_LIMIT_WINDOW: Joi.number().integer().min(1000).default(900000), // 15 minutes
  
  // File Upload
  MAX_FILE_SIZE: Joi.number().integer().min(1024).default(10485760), // 10MB
  UPLOAD_DIR: Joi.string().optional()
}).unknown(); // Allow other environment variables

/**
 * Validate environment variables
 */
export function validateEnv() {
  const { error, value } = envSchema.validate(process.env);
  
  if (error) {
    logger.error('Environment validation failed:', error.details);
    process.exit(1);
  }
  
  // Warn about missing optional but recommended variables
  const warnings = [];
  
  if (!value.DATABASE_URL && !value.DB_HOST) {
    warnings.push('No database configuration found');
  }
  
  if (!value.REDIS_URL && !value.REDIS_HOST) {
    warnings.push('No Redis configuration found');
  }
  
  if (!value.MASTER_ENCRYPTION_KEY) {
    warnings.push('No master encryption key set - using generated key');
  }
  
  if (value.NODE_ENV === 'production') {
    if (!value.SMTP_HOST) {
      warnings.push('No SMTP configuration in production');
    }
    
    if (value.JWT_SECRET.length < 64) {
      warnings.push('JWT secret should be longer in production');
    }
  }
  
  warnings.forEach(warning => logger.warn(`Environment warning: ${warning}`));
  
  logger.config('Environment', warnings.length === 0, warnings);
  
  return value;
}

/**
 * User registration validation schema
 */
export const registerSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required()
    .messages({
      'string.alphanum': 'Username must contain only alphanumeric characters',
      'string.min': 'Username must be at least 3 characters long',
      'string.max': 'Username must not exceed 30 characters'
    }),
    
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address'
    }),
    
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.max': 'Password must not exceed 128 characters',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    }),
    
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Passwords do not match'
    }),
    
  firstName: Joi.string()
    .min(1)
    .max(50)
    .pattern(/^[a-zA-Z\s-']+$/)
    .optional()
    .messages({
      'string.pattern.base': 'First name can only contain letters, spaces, hyphens, and apostrophes'
    }),
    
  lastName: Joi.string()
    .min(1)
    .max(50)
    .pattern(/^[a-zA-Z\s-']+$/)
    .optional()
    .messages({
      'string.pattern.base': 'Last name can only contain letters, spaces, hyphens, and apostrophes'
    }),
    
  agreeToTerms: Joi.boolean()
    .valid(true)
    .required()
    .messages({
      'any.only': 'You must agree to the terms and conditions'
    })
});

/**
 * User login validation schema
 */
export const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .required(),
    
  password: Joi.string()
    .min(1)
    .max(128)
    .required(),
    
  rememberMe: Joi.boolean()
    .optional()
    .default(false)
});

/**
 * Password reset request schema
 */
export const passwordResetRequestSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
});

/**
 * Password reset schema
 */
export const passwordResetSchema = Joi.object({
  token: Joi.string()
    .required(),
    
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    }),
    
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Passwords do not match'
    })
});

/**
 * User profile update schema
 */
export const profileUpdateSchema = Joi.object({
  firstName: Joi.string()
    .min(1)
    .max(50)
    .pattern(/^[a-zA-Z\s-']+$/)
    .optional(),
    
  lastName: Joi.string()
    .min(1)
    .max(50)
    .pattern(/^[a-zA-Z\s-']+$/)
    .optional(),
    
  bio: Joi.string()
    .max(500)
    .optional(),
    
  avatar: Joi.string()
    .uri()
    .optional(),
    
  preferences: Joi.object({
    theme: Joi.string().valid('light', 'dark', 'auto').optional(),
    language: Joi.string().length(2).optional(),
    notifications: Joi.object({
      email: Joi.boolean().optional(),
      push: Joi.boolean().optional(),
      sms: Joi.boolean().optional()
    }).optional()
  }).optional()
});

/**
 * Wheel progress schema
 */
export const wheelProgressSchema = Joi.object({
  stageId: Joi.number()
    .integer()
    .min(1)
    .max(10)
    .required(),
    
  timeSpent: Joi.number()
    .integer()
    .min(0)
    .max(86400) // Max 24 hours
    .required(),
    
  insights: Joi.string()
    .max(2000)
    .optional(),
    
  encrypted: Joi.boolean()
    .optional()
    .default(false),
    
  completedActions: Joi.array()
    .items(Joi.string())
    .optional(),
    
  mood: Joi.string()
    .valid('peaceful', 'contemplative', 'energized', 'emotional', 'confused', 'inspired')
    .optional(),
    
  rating: Joi.number()
    .integer()
    .min(1)
    .max(5)
    .optional()
});

/**
 * File upload validation schema
 */
export const fileUploadSchema = Joi.object({
  filename: Joi.string()
    .max(255)
    .required(),
    
  mimetype: Joi.string()
    .valid(
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'application/pdf',
      'text/plain'
    )
    .required(),
    
  size: Joi.number()
    .integer()
    .max(process.env.MAX_FILE_SIZE || 10485760) // 10MB default
    .required()
});

/**
 * Pagination schema
 */
export const paginationSchema = Joi.object({
  page: Joi.number()
    .integer()
    .min(1)
    .default(1),
    
  limit: Joi.number()
    .integer()
    .min(1)
    .max(100)
    .default(20),
    
  sortBy: Joi.string()
    .valid('createdAt', 'updatedAt', 'name', 'email')
    .default('createdAt'),
    
  sortOrder: Joi.string()
    .valid('asc', 'desc')
    .default('desc')
});

/**
 * Generic ID validation
 */
export const idSchema = Joi.object({
  id: Joi.alternatives()
    .try(
      Joi.number().integer().positive(),
      Joi.string().uuid()
    )
    .required()
});

/**
 * Email validation
 */
export const emailSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
});

/**
 * Search schema
 */
export const searchSchema = Joi.object({
  query: Joi.string()
    .min(1)
    .max(100)
    .required(),
    
  filters: Joi.object({
    category: Joi.string().optional(),
    dateFrom: Joi.date().iso().optional(),
    dateTo: Joi.date().iso().optional(),
    status: Joi.string().optional()
  }).optional()
});

/**
 * Validation middleware factory
 */
export function validate(schema, property = 'body') {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], {
      abortEarly: false,
      stripUnknown: true
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));
      
      logger.warn('Validation failed:', {
        endpoint: req.originalUrl,
        errors,
        ip: req.ip
      });
      
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors
      });
    }
    
    // Replace the property with validated and sanitized value
    req[property] = value;
    next();
  };
}

/**
 * Sanitize HTML input
 */
export function sanitizeHtml(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Validate and sanitize object recursively
 */
export function sanitizeObject(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return sanitizeHtml(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  
  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    sanitized[key] = sanitizeObject(value);
  }
  
  return sanitized;
}

/**
 * Rate limiting validation
 */
export function validateRateLimit(limit, window) {
  return Joi.object({
    limit: Joi.number().integer().min(1).default(limit),
    window: Joi.number().integer().min(1000).default(window)
  }).validate({ limit, window });
}

/**
 * IP address validation
 */
export function isValidIP(ip) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Username validation (stricter than Joi for availability check)
 */
export function validateUsername(username) {
  const errors = [];
  
  if (!username || typeof username !== 'string') {
    errors.push('Username is required');
    return { valid: false, errors };
  }
  
  if (username.length < 3) {
    errors.push('Username must be at least 3 characters long');
  }
  
  if (username.length > 30) {
    errors.push('Username must not exceed 30 characters');
  }
  
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    errors.push('Username can only contain letters, numbers, and underscores');
  }
  
  if (/^[0-9]/.test(username)) {
    errors.push('Username cannot start with a number');
  }
  
  const reserved = ['admin', 'root', 'api', 'www', 'mail', 'ftp', 'localhost', 'wheel', 'turning'];
  if (reserved.includes(username.toLowerCase())) {
    errors.push('This username is reserved');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

export default {
  validateEnv,
  validate,
  sanitizeHtml,
  sanitizeObject,
  validateRateLimit,
  isValidIP,
  validateUsername,
  registerSchema,
  loginSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  profileUpdateSchema,
  wheelProgressSchema,
  fileUploadSchema,
  paginationSchema,
  idSchema,
  emailSchema,
  searchSchema
};
