/**
 * Authentication Routes
 * Handles user registration, login, token refresh, and password management
 */

import express from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';

// Middleware and utilities
import { validate, registerSchema, loginSchema, passwordResetRequestSchema, passwordResetSchema } from '../utils/validation.js';
import { generateTokenPair, refreshTokenMiddleware, logoutMiddleware, authMiddleware } from '../middleware/auth.js';
import { generateUserKeyPair } from '../utils/encryption.js';
import logger from '../utils/logger.js';

// Models (these would be implemented with your database)
import { 
  createUser, 
  getUserByEmail, 
  getUserByUsername,
  updateUserPassword,
  createPasswordResetToken,
  validatePasswordResetToken,
  updateUserLastLogin
} from '../models/User.js';

const router = express.Router();

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many authentication attempts',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.rateLimit(req.ip, req.originalUrl, 5, req.rateLimit.current);
    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many authentication attempts. Please try again later.',
      retryAfter: '15 minutes'
    });
  }
});

// Even stricter for password reset
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour
  message: {
    error: 'Too many password reset attempts',
    retryAfter: '1 hour'
  }
});

/**
 * POST /api/auth/register
 * Register a new user with E2E encryption setup
 */
router.post('/register', authLimiter, validate(registerSchema), async (req, res) => {
  try {
    const { username, email, password, firstName, lastName } = req.body;
    
    // Check if user already exists
    const existingEmail = await getUserByEmail(email);
    if (existingEmail) {
      logger.auth('REGISTER_FAILED', null, { email, reason: 'email_exists', ip: req.ip });
      return res.status(409).json({
        success: false,
        error: 'User already exists',
        message: 'An account with this email already exists'
      });
    }
    
    const existingUsername = await getUserByUsername(username);
    if (existingUsername) {
      logger.auth('REGISTER_FAILED', null, { username, reason: 'username_exists', ip: req.ip });
      return res.status(409).json({
        success: false,
        error: 'Username taken',
        message: 'This username is already taken'
      });
    }
    
    // Hash password
    const saltRounds = process.env.NODE_ENV === 'production' ? 12 : 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Generate user encryption key pair
    const userKeys = generateUserKeyPair(password);
    
    // Create user
    const userData = {
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      firstName,
      lastName,
      encryptionSalt: userKeys.salt,
      isActive: true,
      emailVerified: false,
      createdAt: new Date(),
      lastLogin: null
    };
    
    const user = await createUser(userData);
    
    // Generate tokens
    const tokens = generateTokenPair({
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role || 'user'
    });
    
    // Log successful registration
    logger.auth('REGISTER_SUCCESS', user.id, { 
      email: user.email, 
      username: user.username,
      ip: req.ip 
    });
    
    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          createdAt: user.createdAt
        },
        tokens,
        encryption: {
          userKey: userKeys.key,
          algorithm: userKeys.algorithm
        }
      }
    });
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/register',
      email: req.body?.email,
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Registration failed',
      message: 'Unable to create account. Please try again.'
    });
  }
});

/**
 * POST /api/auth/login
 * Authenticate user and return tokens
 */
router.post('/login', authLimiter, validate(loginSchema), async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    
    // Get user by email
    const user = await getUserByEmail(email.toLowerCase());
    if (!user) {
      logger.auth('LOGIN_FAILED', null, { email, reason: 'user_not_found', ip: req.ip });
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }
    
    // Check if account is active
    if (!user.isActive) {
      logger.auth('LOGIN_FAILED', user.id, { email, reason: 'account_disabled', ip: req.ip });
      return res.status(401).json({
        success: false,
        error: 'Account disabled',
        message: 'Your account has been disabled. Please contact support.'
      });
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      logger.auth('LOGIN_FAILED', user.id, { email, reason: 'invalid_password', ip: req.ip });
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }
    
    // Generate user encryption key
    const userKeys = generateUserKeyPair(password, Buffer.from(user.encryptionSalt, 'base64'));
    
    // Generate tokens with extended expiry if rememberMe
    const tokenPayload = {
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role || 'user'
    };
    
    const tokens = generateTokenPair(tokenPayload);
    
    // Update last login
    await updateUserLastLogin(user.id);
    
    // Log successful login
    logger.auth('LOGIN_SUCCESS', user.id, { 
      email: user.email,
      rememberMe,
      ip: req.ip 
    });
    
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          lastLogin: new Date(),
          emailVerified: user.emailVerified
        },
        tokens,
        encryption: {
          userKey: userKeys.key,
          algorithm: userKeys.algorithm
        }
      }
    });
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/login',
      email: req.body?.email,
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Login failed',
      message: 'Unable to authenticate. Please try again.'
    });
  }
});

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh', refreshTokenMiddleware, async (req, res) => {
  try {
    const user = req.user;
    
    // Generate new token pair
    const tokens = generateTokenPair({
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role
    });
    
    logger.auth('TOKEN_REFRESH', user.id, { ip: req.ip });
    
    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        tokens
      }
    });
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/refresh',
      userId: req.user?.id,
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Token refresh failed',
      message: 'Unable to refresh token. Please login again.'
    });
  }
});

/**
 * POST /api/auth/logout
 * Logout user and blacklist tokens
 */
router.post('/logout', authMiddleware, logoutMiddleware, async (req, res) => {
  try {
    logger.auth('LOGOUT', req.user.id, { ip: req.ip });
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/logout',
      userId: req.user?.id,
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Logout failed',
      message: 'Unable to logout properly. Please clear your local storage.'
    });
  }
});

/**
 * POST /api/auth/password-reset-request
 * Request password reset token
 */
router.post('/password-reset-request', resetLimiter, validate(passwordResetRequestSchema), async (req, res) => {
  try {
    const { email } = req.body;
    
    // Get user by email
    const user = await getUserByEmail(email.toLowerCase());
    
    // Always return success to prevent email enumeration
    const successResponse = {
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.'
    };
    
    if (!user) {
      logger.auth('PASSWORD_RESET_REQUEST_FAILED', null, { 
        email, 
        reason: 'user_not_found',
        ip: req.ip 
      });
      return res.json(successResponse);
    }
    
    if (!user.isActive) {
      logger.auth('PASSWORD_RESET_REQUEST_FAILED', user.id, { 
        email, 
        reason: 'account_disabled',
        ip: req.ip 
      });
      return res.json(successResponse);
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    await createPasswordResetToken(user.id, resetToken, resetExpiry);
    
    // TODO: Send email with reset link
    // await sendPasswordResetEmail(user.email, resetToken);
    
    logger.auth('PASSWORD_RESET_REQUEST', user.id, { 
      email: user.email,
      ip: req.ip 
    });
    
    res.json(successResponse);
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/password-reset-request',
      email: req.body?.email,
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Password reset request failed',
      message: 'Unable to process password reset request. Please try again.'
    });
  }
});

/**
 * POST /api/auth/password-reset
 * Reset password using token
 */
router.post('/password-reset', resetLimiter, validate(passwordResetSchema), async (req, res) => {
  try {
    const { token, password } = req.body;
    
    // Validate reset token
    const user = await validatePasswordResetToken(token);
    if (!user) {
      logger.auth('PASSWORD_RESET_FAILED', null, { 
        reason: 'invalid_token',
        ip: req.ip 
      });
      return res.status(400).json({
        success: false,
        error: 'Invalid reset token',
        message: 'The password reset token is invalid or has expired.'
      });
    }
    
    // Hash new password
    const saltRounds = process.env.NODE_ENV === 'production' ? 12 : 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Generate new encryption salt (user will need to re-enter data)
    const newSalt = crypto.randomBytes(32).toString('base64');
    
    // Update password and encryption salt
    await updateUserPassword(user.id, hashedPassword, newSalt);
    
    logger.auth('PASSWORD_RESET_SUCCESS', user.id, { 
      email: user.email,
      ip: req.ip 
    });
    
    res.json({
      success: true,
      message: 'Password reset successfully. Please login with your new password.',
      note: 'Your encrypted data will need to be re-entered due to security requirements.'
    });
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/password-reset',
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Password reset failed',
      message: 'Unable to reset password. Please try again.'
    });
  }
});

/**
 * GET /api/auth/me
 * Get current user information
 */
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isActive: user.isActive,
          emailVerified: user.emailVerified,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt
        }
      }
    });
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/me',
      userId: req.user?.id,
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Unable to fetch user information',
      message: 'Please try again later.'
    });
  }
});

/**
 * POST /api/auth/verify-token
 * Verify if current token is valid
 */
router.post('/verify-token', authMiddleware, async (req, res) => {
  // If we reach here, token is valid (authMiddleware passed)
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      userId: req.user.id,
      expiresAt: req.token.exp * 1000, // Convert to milliseconds
      issuedAt: req.token.iat * 1000
    }
  });
});

/**
 * POST /api/auth/change-password
 * Change password for authenticated user
 */
router.post('/change-password', authMiddleware, validate(Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).required(),
  confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required()
})), async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;
    
    // Get user with password
    const user = await getUserById(userId, true); // Include password
    
    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      logger.auth('PASSWORD_CHANGE_FAILED', userId, { 
        reason: 'invalid_current_password',
        ip: req.ip 
      });
      return res.status(400).json({
        success: false,
        error: 'Invalid current password',
        message: 'The current password you entered is incorrect.'
      });
    }
    
    // Hash new password
    const saltRounds = process.env.NODE_ENV === 'production' ? 12 : 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Generate new encryption salt
    const newSalt = crypto.randomBytes(32).toString('base64');
    
    // Update password
    await updateUserPassword(userId, hashedPassword, newSalt);
    
    logger.auth('PASSWORD_CHANGE_SUCCESS', userId, { ip: req.ip });
    
    res.json({
      success: true,
      message: 'Password changed successfully',
      note: 'You will need to re-enter any encrypted data due to security requirements.'
    });
    
  } catch (error) {
    logger.errorLog(error, { 
      endpoint: '/auth/change-password',
      userId: req.user?.id,
      ip: req.ip 
    });
    
    res.status(500).json({
      success: false,
      error: 'Password change failed',
      message: 'Unable to change password. Please try again.'
    });
  }
});

export default router;
