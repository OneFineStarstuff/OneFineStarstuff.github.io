/**
 * Winston Logger Configuration
 * Provides structured logging with multiple transports and security features
 */

import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Log directory
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '../logs');

// Environment configuration
const NODE_ENV = process.env.NODE_ENV || 'development';
const LOG_LEVEL = process.env.LOG_LEVEL || (NODE_ENV === 'production' ? 'info' : 'debug');

// Security: fields to redact from logs
const SENSITIVE_FIELDS = [
  'password',
  'token',
  'authorization',
  'cookie',
  'secret',
  'key',
  'apikey',
  'api_key',
  'access_token',
  'refresh_token',
  'jwt',
  'bearer',
  'auth',
  'credentials',
  'credit_card',
  'ssn',
  'social_security',
  'encrypted',
  'signature'
];

/**
 * Redact sensitive information from log data
 */
function redactSensitiveData(obj, depth = 0) {
  if (depth > 10) return '[Max Depth Reached]'; // Prevent infinite recursion
  
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => redactSensitiveData(item, depth + 1));
  }
  
  const redacted = {};
  
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    
    // Check if field should be redacted
    const shouldRedact = SENSITIVE_FIELDS.some(field => 
      lowerKey.includes(field) || 
      lowerKey === field ||
      lowerKey.endsWith('_' + field) ||
      lowerKey.startsWith(field + '_')
    );
    
    if (shouldRedact) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redactSensitiveData(value, depth + 1);
    } else {
      redacted[key] = value;
    }
  }
  
  return redacted;
}

/**
 * Custom log format
 */
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    // Redact sensitive data from meta
    const safeMeta = redactSensitiveData(meta);
    
    const logEntry = {
      timestamp,
      level: level.toUpperCase(),
      message,
      ...(stack && { stack }),
      ...(Object.keys(safeMeta).length > 0 && { meta: safeMeta })
    };
    
    return JSON.stringify(logEntry);
  })
);

/**
 * Console format for development
 */
const consoleFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'HH:mm:ss.SSS'
  }),
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    const safeMeta = redactSensitiveData(meta);
    const metaStr = Object.keys(safeMeta).length > 0 
      ? '\n' + JSON.stringify(safeMeta, null, 2)
      : '';
    
    if (stack) {
      return `${timestamp} [${level}] ${message}\n${stack}${metaStr}`;
    }
    
    return `${timestamp} [${level}] ${message}${metaStr}`;
  })
);

/**
 * Create logger transports
 */
const transports = [];

// Console transport for development
if (NODE_ENV === 'development') {
  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
      level: LOG_LEVEL
    })
  );
} else {
  // Simple console for production
  transports.push(
    new winston.transports.Console({
      format: logFormat,
      level: LOG_LEVEL
    })
  );
}

// File transport for all logs
transports.push(
  new DailyRotateFile({
    filename: path.join(LOG_DIR, 'application-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '14d',
    format: logFormat,
    level: LOG_LEVEL
  })
);

// Error log file
transports.push(
  new DailyRotateFile({
    filename: path.join(LOG_DIR, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    format: logFormat,
    level: 'error'
  })
);

// Audit log for security events
transports.push(
  new DailyRotateFile({
    filename: path.join(LOG_DIR, 'audit-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '90d',
    format: logFormat,
    level: 'info'
  })
);

/**
 * Create logger instance
 */
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: logFormat,
  defaultMeta: {
    service: 'turning-wheel-api',
    version: process.env.npm_package_version || '1.0.0',
    environment: NODE_ENV,
    pid: process.pid,
    hostname: require('os').hostname()
  },
  transports,
  exitOnError: false,
  
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(LOG_DIR, 'exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
      format: logFormat
    })
  ],
  
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(LOG_DIR, 'rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
      format: logFormat
    })
  ]
});

/**
 * Security audit logging
 */
export function auditLog(event, details = {}) {
  logger.info(`AUDIT: ${event}`, {
    audit: true,
    event,
    ...details,
    timestamp: new Date().toISOString()
  });
}

/**
 * Authentication event logging
 */
export function authLog(event, userId, details = {}) {
  auditLog(`AUTH_${event}`, {
    userId,
    ...details
  });
}

/**
 * Request logging with sanitization
 */
export function requestLog(req, res, responseTime) {
  const { method, url, ip, headers, body, query, params } = req;
  
  logger.info('HTTP Request', {
    request: {
      method,
      url,
      ip,
      userAgent: headers['user-agent'],
      headers: redactSensitiveData(headers),
      body: redactSensitiveData(body),
      query: redactSensitiveData(query),
      params: redactSensitiveData(params)
    },
    response: {
      statusCode: res.statusCode,
      contentLength: res.get('content-length'),
      responseTime: `${responseTime}ms`
    },
    userId: req.user?.id || 'anonymous'
  });
}

/**
 * Error logging with context
 */
export function errorLog(error, context = {}) {
  logger.error('Application Error', {
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: error.code
    },
    context: redactSensitiveData(context)
  });
}

/**
 * Performance monitoring
 */
export function performanceLog(operation, duration, metadata = {}) {
  logger.info('Performance Metric', {
    performance: {
      operation,
      duration: `${duration}ms`,
      ...metadata
    }
  });
}

/**
 * Database operation logging
 */
export function dbLog(operation, table, duration, metadata = {}) {
  logger.debug('Database Operation', {
    database: {
      operation,
      table,
      duration: `${duration}ms`,
      ...redactSensitiveData(metadata)
    }
  });
}

/**
 * Encryption operation logging
 */
export function cryptoLog(operation, success = true, metadata = {}) {
  logger.info('Crypto Operation', {
    crypto: {
      operation,
      success,
      ...redactSensitiveData(metadata)
    }
  });
}

/**
 * Rate limiting events
 */
export function rateLimitLog(ip, endpoint, limit, current) {
  logger.warn('Rate Limit Event', {
    rateLimit: {
      ip,
      endpoint,
      limit,
      current,
      exceeded: current >= limit
    }
  });
}

/**
 * Configuration validation logging
 */
export function configLog(component, valid, issues = []) {
  logger.info('Configuration Check', {
    config: {
      component,
      valid,
      issues
    }
  });
}

/**
 * Health check logging
 */
export function healthLog(component, status, details = {}) {
  const level = status === 'healthy' ? 'info' : 'warn';
  
  logger[level]('Health Check', {
    health: {
      component,
      status,
      ...details
    }
  });
}

/**
 * Startup logging
 */
export function startupLog(component, status, details = {}) {
  logger.info('Startup Event', {
    startup: {
      component,
      status,
      ...details
    }
  });
}

/**
 * Shutdown logging
 */
export function shutdownLog(component, reason, details = {}) {
  logger.info('Shutdown Event', {
    shutdown: {
      component,
      reason,
      ...details
    }
  });
}

// Add custom methods to logger
logger.audit = auditLog;
logger.auth = authLog;
logger.request = requestLog;
logger.errorLog = errorLog;
logger.performance = performanceLog;
logger.db = dbLog;
logger.crypto = cryptoLog;
logger.rateLimit = rateLimitLog;
logger.config = configLog;
logger.health = healthLog;
logger.startup = startupLog;
logger.shutdown = shutdownLog;

// Stream interface for Morgan
logger.stream = {
  write: (message) => {
    logger.info(message.trim());
  }
};

export default logger;
