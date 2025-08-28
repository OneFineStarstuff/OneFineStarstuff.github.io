/**
 * JWT Authentication Middleware
 * Provides secure token-based authentication with refresh tokens
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import logger from '../utils/logger.js';
import { getUserById, updateUserLastSeen } from '../models/User.js';
import { isTokenBlacklisted, blacklistToken } from '../utils/tokenBlacklist.js';

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = process.env.JWT_EXPIRY || '15m';
const JWT_REFRESH_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d';

/**
 * Generate JWT access token
 */
export function generateAccessToken(payload) {
  return jwt.sign(
    {
      ...payload,
      type: 'access',
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID() // JWT ID for tracking
    },
    JWT_SECRET,
    {
      expiresIn: JWT_EXPIRY,
      algorithm: 'HS256',
      issuer: 'turning-wheel-api',
      audience: 'turning-wheel-client'
    }
  );
}

/**
 * Generate JWT refresh token
 */
export function generateRefreshToken(payload) {
  return jwt.sign(
    {
      userId: payload.userId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID()
    },
    JWT_REFRESH_SECRET,
    {
      expiresIn: JWT_REFRESH_EXPIRY,
      algorithm: 'HS256',
      issuer: 'turning-wheel-api',
      audience: 'turning-wheel-client'
    }
  );
}

/**
 * Verify JWT token
 */
export function verifyToken(token, isRefresh = false) {
  try {
    const secret = isRefresh ? JWT_REFRESH_SECRET : JWT_SECRET;
    const decoded = jwt.verify(token, secret, {
      algorithms: ['HS256'],
      issuer: 'turning-wheel-api',
      audience: 'turning-wheel-client'
    });
    
    return {
      valid: true,
      decoded,
      expired: false
    };
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return {
        valid: false,
        decoded: null,
        expired: true,
        error: 'Token expired'
      };
    }
    
    if (error instanceof jwt.JsonWebTokenError) {
      return {
        valid: false,
        decoded: null,
        expired: false,
        error: 'Invalid token'
      };
    }
    
    return {
      valid: false,
      decoded: null,
      expired: false,
      error: error.message
    };
  }
}

/**
 * Authentication middleware
 */
export async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        message: 'No valid authorization header provided'
      });
    }
    
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    // Check if token is blacklisted
    if (await isTokenBlacklisted(token)) {
      return res.status(401).json({
        success: false,
        error: 'Token invalidated',
        message: 'This token has been revoked'
      });
    }
    
    const verification = verifyToken(token);
    
    if (!verification.valid) {
      if (verification.expired) {
        return res.status(401).json({
          success: false,
          error: 'Token expired',
          message: 'Please refresh your token',
          code: 'TOKEN_EXPIRED'
        });
      }
      
      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        message: verification.error
      });
    }
    
    const { decoded } = verification;
    
    // Verify token type
    if (decoded.type !== 'access') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token type',
        message: 'Access token required'
      });
    }
    
    // Get user information
    const user = await getUserById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found',
        message: 'Token refers to non-existent user'
      });
    }
    
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'Account disabled',
        message: 'Your account has been disabled'
      });
    }
    
    // Update last seen (async, don't wait)
    updateUserLastSeen(user.id).catch(err => 
      logger.warn(`Failed to update last seen for user ${user.id}:`, err)
    );
    
    // Add user and token info to request
    req.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      isActive: user.isActive,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt
    };
    
    req.token = {
      jti: decoded.jti,
      iat: decoded.iat,
      exp: decoded.exp,
      raw: token
    };
    
    next();
  } catch (error) {
    logger.error('Authentication middleware error:', error);
    return res.status(500).json({
      success: false,
      error: 'Authentication error',
      message: 'Internal server error during authentication'
    });
  }
}

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
export async function optionalAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    req.token = null;
    return next();
  }
  
  try {
    await authMiddleware(req, res, next);
  } catch (error) {
    // If optional auth fails, continue without user
    req.user = null;
    req.token = null;
    next();
  }
}

/**
 * Role-based authorization middleware
 */
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        message: 'Must be logged in to access this resource'
      });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
        message: `Requires one of the following roles: ${roles.join(', ')}`
      });
    }
    
    next();
  };
}

/**
 * Refresh token middleware
 */
export async function refreshTokenMiddleware(req, res, next) {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'Refresh token required',
        message: 'Refresh token must be provided'
      });
    }
    
    // Check if refresh token is blacklisted
    if (await isTokenBlacklisted(refreshToken)) {
      return res.status(401).json({
        success: false,
        error: 'Token invalidated',
        message: 'This refresh token has been revoked'
      });
    }
    
    const verification = verifyToken(refreshToken, true);
    
    if (!verification.valid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
        message: verification.error
      });
    }
    
    const { decoded } = verification;
    
    // Verify token type
    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token type',
        message: 'Refresh token required'
      });
    }
    
    // Get user information
    const user = await getUserById(decoded.userId);
    
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'Invalid user',
        message: 'User not found or inactive'
      });
    }
    
    req.user = user;
    req.refreshToken = {
      jti: decoded.jti,
      iat: decoded.iat,
      exp: decoded.exp,
      raw: refreshToken
    };
    
    next();
  } catch (error) {
    logger.error('Refresh token middleware error:', error);
    return res.status(500).json({
      success: false,
      error: 'Token refresh error',
      message: 'Internal server error during token refresh'
    });
  }
}

/**
 * Logout middleware - blacklist tokens
 */
export async function logoutMiddleware(req, res, next) {
  try {
    const promises = [];
    
    // Blacklist access token
    if (req.token?.raw) {
      promises.push(blacklistToken(req.token.raw, req.token.exp));
    }
    
    // Blacklist refresh token if provided
    const { refreshToken } = req.body;
    if (refreshToken) {
      const verification = verifyToken(refreshToken, true);
      if (verification.valid) {
        promises.push(blacklistToken(refreshToken, verification.decoded.exp));
      }
    }
    
    await Promise.all(promises);
    
    logger.info(`User ${req.user?.id} logged out successfully`);
    
    next();
  } catch (error) {
    logger.error('Logout middleware error:', error);
    // Continue with logout even if blacklisting fails
    next();
  }
}

/**
 * Generate token pair (access + refresh)
 */
export function generateTokenPair(payload) {
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);
  
  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: JWT_EXPIRY,
    issuedAt: new Date().toISOString()
  };
}

/**
 * Extract token from request
 */
export function extractTokenFromRequest(req) {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Also check query parameter as fallback (for WebSocket)
  return req.query.token || null;
}

export default {
  authMiddleware,
  optionalAuthMiddleware,
  requireRole,
  refreshTokenMiddleware,
  logoutMiddleware,
  generateAccessToken,
  generateRefreshToken,
  generateTokenPair,
  verifyToken,
  extractTokenFromRequest
};
