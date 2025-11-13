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
 * Generates a JWT access token with the given payload.
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
 * Generates a JWT refresh token.
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
 * Verify JWT token.
 *
 * This function checks the validity of a JWT token using a specified secret based on whether it is a refresh token or not.
 * It decodes the token and returns an object indicating its validity, the decoded payload, and whether it has expired.
 * If an error occurs during verification, it handles different error types to provide specific feedback on the token's status.
 *
 * @param {string} token - The JWT token to verify.
 * @param {boolean} [isRefresh=false] - Indicates if the token is a refresh token.
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
 * Authentication middleware for validating user tokens.
 *
 * This middleware checks for a valid Bearer token in the authorization header, verifies its validity and type,
 * and retrieves user information. It handles various authentication errors, including blacklisted tokens,
 * expired tokens, and inactive accounts, responding with appropriate status codes and messages.
 * If successful, it attaches user and token information to the request object for further processing.
 *
 * @param req - The request object containing the HTTP request data.
 * @param res - The response object used to send HTTP responses.
 * @param next - The next middleware function in the stack.
 * @throws Error If an internal error occurs during authentication.
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
 * Optional authentication middleware that allows requests to proceed without a token.
 *
 * This middleware checks for the presence of an authorization header. If the header is missing or does not start with 'Bearer ', it sets req.user and req.token to null and calls next() to continue the request. If the header is present, it attempts to call the authMiddleware function. If authMiddleware throws an error, it catches the error, sets req.user and req.token to null, and continues the request.
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
 * Role-based authorization middleware.
 *
 * This middleware checks if the user is authenticated and has one of the required roles.
 * If the user is not authenticated, a 401 status is returned with an appropriate message.
 * If the user's role is not included in the specified roles, a 403 status is returned,
 * indicating insufficient permissions. If both checks pass, the middleware calls the next function.
 *
 * @param {...string} roles - The roles that are required to access the resource.
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
 * Middleware to refresh the token for authenticated users.
 *
 * This function checks for the presence of a refresh token in the request body, verifies its validity, and ensures it is not blacklisted.
 * It also checks the token type and retrieves the associated user information, attaching it to the request object for further processing.
 * If any validation fails, appropriate error responses are sent back to the client.
 *
 * @param req - The request object containing the refresh token in the body.
 * @param res - The response object used to send responses back to the client.
 * @param next - The next middleware function in the stack.
 * @throws Error If an internal server error occurs during the token refresh process.
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
 * Logout middleware - blacklist tokens.
 *
 * This middleware handles the logout process by blacklisting the access token and, if provided, the refresh token.
 * It checks for the presence of the access token and blacklists it if available. If a refresh token is included in
 * the request body, it verifies the token and blacklists it if valid. The function logs the logout action and
 * proceeds to the next middleware, even if an error occurs during the blacklisting process.
 *
 * @param {Object} req - The request object containing user and token information.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function to call.
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
 * Generates a token pair (access + refresh) from the given payload.
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
 * Extract token from request.
 *
 * This function retrieves a token from the provided request object. It first checks the
 * authorization header for a Bearer token and returns it if present. If the header is
 * not available or does not contain a Bearer token, it falls back to checking the query
 * parameters for a token, specifically for WebSocket scenarios.
 *
 * @param {Object} req - The request object containing headers and query parameters.
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
