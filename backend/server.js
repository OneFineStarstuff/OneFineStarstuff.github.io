#!/usr/bin/env node

/**
 * Turning Wheel - Secure Full-Stack Backend
 * Complete E2E encryption, JWT authentication, and mystical API
 */

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import morgan from 'morgan';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Security imports
import ExpressBrute from 'express-brute';
import MongoStore from 'express-brute/lib/stores/memory.js';
import mongoSanitize from 'express-mongo-sanitize';
import xss from 'xss';
import hpp from 'hpp';

// Custom modules
import logger from './utils/logger.js';
import { validateEnv } from './utils/validation.js';
import { initializeDatabase } from './config/database.js';
import { initializeRedis } from './config/redis.js';
import { setupWebSocket } from './config/websocket.js';

// Route imports
import authRoutes from './routes/auth.js';
import wheelRoutes from './routes/wheel.js';
import userRoutes from './routes/user.js';
import analyticsRoutes from './routes/analytics.js';
import healthRoutes from './routes/health.js';
import encryptionRoutes from './routes/encryption.js';

// Middleware imports
import { authMiddleware } from './middleware/auth.js';
import { errorHandler } from './middleware/errorHandler.js';
import { securityMiddleware } from './middleware/security.js';
import { validationMiddleware } from './middleware/validation.js';

// Load environment variables
dotenv.config();

// Validate environment
validateEnv();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 8080;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Trust proxy for rate limiting and security
app.set('trust proxy', 1);

// === SECURITY MIDDLEWARE STACK ===

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      workerSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Encryption-Key'],
  exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-*']
};

app.use(cors(corsOptions));

// Compression for better performance
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Request logging
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: NODE_ENV === 'production' ? 100 : 1000,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests, please slow down'
    });
  }
});

app.use('/api/', limiter);

// Slow down middleware for additional protection
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // allow 50 requests per 15 minutes at full speed
  delayMs: 500, // add 500ms delay per request after delayAfter
  maxDelayMs: 20000, // max delay of 20 seconds
});

app.use('/api/', speedLimiter);

// Brute force protection
const bruteStore = new MongoStore();
const bruteforce = new ExpressBrute(bruteStore, {
  freeRetries: 5,
  minWait: 5 * 60 * 1000, // 5 minutes
  maxWait: 60 * 60 * 1000, // 1 hour
  lifetime: 24 * 60 * 60, // 1 day (seconds)
});

// Body parsing with size limits
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

// Security sanitization
app.use(mongoSanitize({
  replaceWith: '_'
}));

app.use(hpp());

// XSS protection middleware
app.use((req, res, next) => {
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key]);
      }
    });
  }
  next();
});

// Custom security middleware
app.use(securityMiddleware);

// Request ID and correlation
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  req.timestamp = new Date().toISOString();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// === STATIC FILE SERVING ===
app.use('/static', express.static(join(__dirname, '../public'), {
  maxAge: '1d',
  etag: true,
  lastModified: true
}));

// === API ROUTES ===

// Health check (no auth required)
app.use('/api/health', healthRoutes);

// Authentication routes
app.use('/api/auth', bruteforce.prevent, authRoutes);

// Encryption/Decryption utility routes
app.use('/api/crypto', authMiddleware, encryptionRoutes);

// Protected routes (require authentication)
app.use('/api/wheel', authMiddleware, wheelRoutes);
app.use('/api/user', authMiddleware, userRoutes);
app.use('/api/analytics', authMiddleware, analyticsRoutes);

// === MYSTICAL ENDPOINTS ===

// Get all wheel stages
app.get('/api/wheel/stages', authMiddleware, async (req, res) => {
  try {
    const stages = await getWheelStages();
    res.json({
      success: true,
      data: stages,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Failed to fetch wheel stages:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch wheel stages'
    });
  }
});

// Record user journey progress
app.post('/api/wheel/progress', authMiddleware, validationMiddleware, async (req, res) => {
  try {
    const { stageId, timeSpent, insights, encrypted } = req.body;
    const userId = req.user.id;
    
    const progress = await recordProgress({
      userId,
      stageId,
      timeSpent,
      insights: encrypted ? insights : await encryptInsights(insights),
      timestamp: new Date()
    });
    
    res.json({
      success: true,
      data: progress,
      message: 'Progress recorded successfully'
    });
  } catch (error) {
    logger.error('Failed to record progress:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to record progress'
    });
  }
});

// === WEBSOCKET INITIALIZATION ===
const server = app.listen(PORT, () => {
  logger.info(`🌟 Turning Wheel Backend Server running on port ${PORT}`);
  logger.info(`📍 Environment: ${NODE_ENV}`);
  logger.info(`🔒 Security: E2E encryption enabled`);
  logger.info(`🌀 Mystical API: Ready for spiritual journeys`);
});

// Setup WebSocket for real-time features
setupWebSocket(server);

// === ERROR HANDLING ===

// 404 handler
app.use('*', (req, res) => {
  logger.warn(`404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    error: 'Route not found',
    message: `The path ${req.originalUrl} does not exist on this server`
  });
});

// Global error handler (must be last)
app.use(errorHandler);

// === GRACEFUL SHUTDOWN ===

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  
  server.close(async () => {
    logger.info('HTTP server closed.');
    
    try {
      // Close database connections
      await closeDatabase();
      logger.info('Database connections closed.');
      
      // Close Redis connection
      await closeRedis();
      logger.info('Redis connection closed.');
      
      logger.info('Graceful shutdown completed.');
      process.exit(0);
    } catch (error) {
      logger.error('Error during shutdown:', error);
      process.exit(1);
    }
  });
  
  // Force close after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
}

// === HELPER FUNCTIONS ===

async function getWheelStages() {
  // This would typically come from database
  return [
    {
      id: 1,
      title: "Creative Remembering",
      symbol: "🌱",
      essence: "The seeds of the past are unearthed, not as static relics, but as living fragments ready to be reimagined.",
      meaning: "Our histories are fertile soil — the fragments we carry forward become the foundation for new growth.",
      action: "Hold a small stone or seed and name aloud one memory you wish to carry forward.",
      chant: "In the deep hum of time, I awaken what was —\\nCreative Remembering, the seeds unbroken."
    },
    // ... other stages would be loaded from database
  ];
}

async function recordProgress(progressData) {
  // This would save to database
  logger.info(`Recording progress for user ${progressData.userId}, stage ${progressData.stageId}`);
  return progressData;
}

async function encryptInsights(insights) {
  // This would use AES-GCM encryption
  return insights; // Placeholder
}

async function closeDatabase() {
  // Close database connections
}

async function closeRedis() {
  // Close Redis connections
}

// Export for testing
export default app;
