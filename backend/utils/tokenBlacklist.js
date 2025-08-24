/**
 * Token Blacklist Utility
 * Manages blacklisted JWT tokens for secure logout and token invalidation
 */

import { query } from '../config/database.js';
import logger from './logger.js';

// In-memory cache for frequently checked tokens (optional Redis could be used here)
const tokenCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Initialize token blacklist table
 */
export async function initializeTokenBlacklist() {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS blacklisted_tokens (
        id SERIAL PRIMARY KEY,
        token_hash VARCHAR(64) UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        blacklisted_at TIMESTAMPTZ DEFAULT NOW(),
        reason VARCHAR(100) DEFAULT 'logout'
      );
    `);

    await query(`
      CREATE INDEX IF NOT EXISTS idx_blacklisted_tokens_hash ON blacklisted_tokens(token_hash);
      CREATE INDEX IF NOT EXISTS idx_blacklisted_tokens_expires ON blacklisted_tokens(expires_at);
    `);

    // Clean up expired tokens periodically
    await cleanupExpiredTokens();

    logger.startup('TokenBlacklist', 'initialized');
  } catch (error) {
    logger.error('Failed to initialize token blacklist:', error);
    throw error;
  }
}

/**
 * Add token to blacklist
 */
export async function blacklistToken(token, expiresAt, reason = 'logout') {
  try {
    if (!token) {
      throw new Error('Token is required');
    }

    // Hash the token for security (don't store full token)
    const tokenHash = hashToken(token);
    
    // Convert Unix timestamp to Date if needed
    const expirationDate = typeof expiresAt === 'number' 
      ? new Date(expiresAt * 1000) 
      : new Date(expiresAt);

    await query(`
      INSERT INTO blacklisted_tokens (token_hash, expires_at, reason)
      VALUES ($1, $2, $3)
      ON CONFLICT (token_hash) DO NOTHING
    `, [tokenHash, expirationDate, reason]);

    // Add to cache
    tokenCache.set(tokenHash, {
      blacklisted: true,
      expiresAt: expirationDate.getTime(),
      cachedAt: Date.now()
    });

    logger.audit('TOKEN_BLACKLISTED', {
      tokenHash: tokenHash.substring(0, 8) + '...',
      reason,
      expiresAt: expirationDate
    });

  } catch (error) {
    logger.error('Failed to blacklist token:', error);
    throw error;
  }
}

/**
 * Check if token is blacklisted
 */
export async function isTokenBlacklisted(token) {
  try {
    if (!token) {
      return false;
    }

    const tokenHash = hashToken(token);

    // Check cache first
    const cached = tokenCache.get(tokenHash);
    if (cached) {
      // Check if cache entry is still valid
      if (Date.now() - cached.cachedAt < CACHE_TTL) {
        // Check if token has expired
        if (cached.expiresAt && Date.now() > cached.expiresAt) {
          tokenCache.delete(tokenHash);
          return false;
        }
        return cached.blacklisted;
      } else {
        // Cache entry is stale
        tokenCache.delete(tokenHash);
      }
    }

    // Check database
    const result = await query(`
      SELECT 1 FROM blacklisted_tokens 
      WHERE token_hash = $1 AND expires_at > NOW()
    `, [tokenHash]);

    const isBlacklisted = result.rows.length > 0;

    // Cache the result
    tokenCache.set(tokenHash, {
      blacklisted: isBlacklisted,
      expiresAt: null, // We'll let the database handle expiration
      cachedAt: Date.now()
    });

    return isBlacklisted;

  } catch (error) {
    logger.error('Failed to check token blacklist:', error);
    // In case of error, allow the token (fail open for availability)
    return false;
  }
}

/**
 * Blacklist all tokens for a user (useful for account compromise)
 */
export async function blacklistAllUserTokens(userId, reason = 'security_breach') {
  try {
    // This would require storing user ID with tokens or implementing a different strategy
    // For now, we'll just log the action and rely on token expiration
    logger.audit('ALL_USER_TOKENS_BLACKLISTED', {
      userId,
      reason
    });

    // In a more sophisticated implementation, you might:
    // 1. Store user_id with tokens
    // 2. Maintain a user blacklist with timestamps
    // 3. Use Redis with user-specific keys

  } catch (error) {
    logger.error('Failed to blacklist all user tokens:', error);
    throw error;
  }
}

/**
 * Clean up expired tokens from database and cache
 */
export async function cleanupExpiredTokens() {
  try {
    const result = await query(`
      DELETE FROM blacklisted_tokens 
      WHERE expires_at <= NOW()
    `);

    if (result.rowCount > 0) {
      logger.info(`Cleaned up ${result.rowCount} expired blacklisted tokens`);
    }

    // Clean up expired cache entries
    const now = Date.now();
    for (const [tokenHash, entry] of tokenCache.entries()) {
      if (entry.expiresAt && now > entry.expiresAt) {
        tokenCache.delete(tokenHash);
      } else if (now - entry.cachedAt > CACHE_TTL * 2) {
        // Remove stale cache entries
        tokenCache.delete(tokenHash);
      }
    }

  } catch (error) {
    logger.error('Failed to cleanup expired tokens:', error);
  }
}

/**
 * Get blacklist statistics
 */
export async function getBlacklistStats() {
  try {
    const result = await query(`
      SELECT 
        COUNT(*) as total_blacklisted,
        COUNT(CASE WHEN expires_at > NOW() THEN 1 END) as active_blacklisted,
        MIN(blacklisted_at) as oldest_entry,
        MAX(blacklisted_at) as newest_entry
      FROM blacklisted_tokens
    `);

    const stats = result.rows[0];

    return {
      totalBlacklisted: parseInt(stats.total_blacklisted),
      activeBlacklisted: parseInt(stats.active_blacklisted),
      oldestEntry: stats.oldest_entry,
      newestEntry: stats.newest_entry,
      cacheSize: tokenCache.size
    };

  } catch (error) {
    logger.error('Failed to get blacklist stats:', error);
    return null;
  }
}

/**
 * Hash token for secure storage
 */
function hashToken(token) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Schedule periodic cleanup
 */
export function scheduleTokenCleanup() {
  // Clean up every hour
  setInterval(async () => {
    try {
      await cleanupExpiredTokens();
    } catch (error) {
      logger.error('Scheduled token cleanup failed:', error);
    }
  }, 60 * 60 * 1000); // 1 hour

  logger.startup('TokenBlacklist', 'cleanup scheduled');
}

/**
 * Clear all blacklisted tokens (use with caution)
 */
export async function clearAllBlacklistedTokens() {
  try {
    const result = await query(`
      DELETE FROM blacklisted_tokens
    `);

    // Clear cache
    tokenCache.clear();

    logger.audit('ALL_BLACKLISTED_TOKENS_CLEARED', {
      tokensCleared: result.rowCount
    });

    return result.rowCount;

  } catch (error) {
    logger.error('Failed to clear all blacklisted tokens:', error);
    throw error;
  }
}

/**
 * Get recently blacklisted tokens (for monitoring)
 */
export async function getRecentlyBlacklistedTokens(limit = 100) {
  try {
    const result = await query(`
      SELECT token_hash, blacklisted_at, expires_at, reason
      FROM blacklisted_tokens
      ORDER BY blacklisted_at DESC
      LIMIT $1
    `, [limit]);

    return result.rows.map(row => ({
      tokenHash: row.token_hash.substring(0, 8) + '...', // Partial hash for security
      blacklistedAt: row.blacklisted_at,
      expiresAt: row.expires_at,
      reason: row.reason
    }));

  } catch (error) {
    logger.error('Failed to get recently blacklisted tokens:', error);
    return [];
  }
}

export default {
  initializeTokenBlacklist,
  blacklistToken,
  isTokenBlacklisted,
  blacklistAllUserTokens,
  cleanupExpiredTokens,
  getBlacklistStats,
  scheduleTokenCleanup,
  clearAllBlacklistedTokens,
  getRecentlyBlacklistedTokens
};
