/**
 * User Model
 * Handles user CRUD operations with encrypted sensitive data
 */

import { query, transaction } from '../config/database.js';
import { encryptField, decryptField } from '../utils/encryption.js';
import logger from '../utils/logger.js';
import crypto from 'crypto';

/**
 * Create a new user
 */
export async function createUser(userData) {
  try {
    const {
      username,
      email,
      password,
      firstName,
      lastName,
      encryptionSalt,
      isActive = true,
      emailVerified = false,
      role = 'user'
    } = userData;

    const result = await query(`
      INSERT INTO users (
        username, email, password_hash, encryption_salt,
        first_name, last_name, is_active, email_verified, role
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id, username, email, first_name, last_name, role,
                is_active, email_verified, created_at
    `, [username, email, password, encryptionSalt, firstName, lastName, isActive, emailVerified, role]);

    const user = result.rows[0];
    
    logger.audit('USER_CREATED', {
      userId: user.id,
      username: user.username,
      email: user.email
    });

    return user;
  } catch (error) {
    logger.error('Failed to create user:', error);
    throw error;
  }
}

/**
 * Get user by ID
 */
export async function getUserById(userId, includePassword = false) {
  try {
    const fields = includePassword 
      ? 'id, username, email, password_hash, encryption_salt, first_name, last_name, role, is_active, email_verified, last_login, created_at, updated_at, preferences, avatar_url, bio'
      : 'id, username, email, encryption_salt, first_name, last_name, role, is_active, email_verified, last_login, created_at, updated_at, preferences, avatar_url, bio';

    const result = await query(`
      SELECT ${fields} FROM users WHERE id = $1
    `, [userId]);

    if (result.rows.length === 0) {
      return null;
    }

    const user = result.rows[0];
    
    // Convert snake_case to camelCase for API consistency
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      ...(includePassword && { password: user.password_hash }),
      encryptionSalt: user.encryption_salt,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      isActive: user.is_active,
      emailVerified: user.email_verified,
      lastLogin: user.last_login,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
      preferences: user.preferences || {},
      avatarUrl: user.avatar_url,
      bio: user.bio
    };
  } catch (error) {
    logger.error('Failed to get user by ID:', error);
    throw error;
  }
}

/**
 * Get user by email
 */
export async function getUserByEmail(email, includePassword = false) {
  try {
    const fields = includePassword 
      ? 'id, username, email, password_hash, encryption_salt, first_name, last_name, role, is_active, email_verified, last_login, created_at, updated_at, preferences, avatar_url, bio'
      : 'id, username, email, encryption_salt, first_name, last_name, role, is_active, email_verified, last_login, created_at, updated_at, preferences, avatar_url, bio';

    const result = await query(`
      SELECT ${fields} FROM users WHERE email = $1
    `, [email.toLowerCase()]);

    if (result.rows.length === 0) {
      return null;
    }

    const user = result.rows[0];
    
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      ...(includePassword && { password: user.password_hash }),
      encryptionSalt: user.encryption_salt,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      isActive: user.is_active,
      emailVerified: user.email_verified,
      lastLogin: user.last_login,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
      preferences: user.preferences || {},
      avatarUrl: user.avatar_url,
      bio: user.bio
    };
  } catch (error) {
    logger.error('Failed to get user by email:', error);
    throw error;
  }
}

/**
 * Get user by username
 */
export async function getUserByUsername(username) {
  try {
    const result = await query(`
      SELECT id, username, email, first_name, last_name, role,
             is_active, email_verified, created_at
      FROM users WHERE username = $1
    `, [username]);

    if (result.rows.length === 0) {
      return null;
    }

    const user = result.rows[0];
    
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      isActive: user.is_active,
      emailVerified: user.email_verified,
      createdAt: user.created_at
    };
  } catch (error) {
    logger.error('Failed to get user by username:', error);
    throw error;
  }
}

/**
 * Update user last login timestamp
 */
export async function updateUserLastLogin(userId) {
  try {
    await query(`
      UPDATE users SET last_login = NOW() WHERE id = $1
    `, [userId]);

    logger.audit('USER_LOGIN', { userId });
  } catch (error) {
    logger.error('Failed to update last login:', error);
    // Don't throw error as this is not critical
  }
}

/**
 * Update user last seen timestamp
 */
export async function updateUserLastSeen(userId) {
  try {
    await query(`
      UPDATE users SET updated_at = NOW() WHERE id = $1
    `, [userId]);
  } catch (error) {
    logger.error('Failed to update last seen:', error);
    // Don't throw error as this is not critical
  }
}

/**
 * Update user password and encryption salt
 */
export async function updateUserPassword(userId, newPasswordHash, newEncryptionSalt) {
  try {
    await transaction(async (client) => {
      // Update password and salt
      await client.query(`
        UPDATE users 
        SET password_hash = $1, encryption_salt = $2, password_reset_token = NULL, password_reset_expires = NULL
        WHERE id = $3
      `, [newPasswordHash, newEncryptionSalt, userId]);

      // Clear all encrypted user data (as it's now unreadable with new salt)
      await client.query(`
        DELETE FROM user_encrypted_data WHERE user_id = $1
      `, [userId]);

      // Invalidate all user sessions
      await client.query(`
        UPDATE user_sessions SET is_active = false WHERE user_id = $1
      `, [userId]);
    });

    logger.audit('PASSWORD_CHANGED', { userId });
  } catch (error) {
    logger.error('Failed to update user password:', error);
    throw error;
  }
}

/**
 * Update user profile
 */
export async function updateUserProfile(userId, profileData) {
  try {
    const {
      firstName,
      lastName,
      bio,
      avatarUrl,
      preferences
    } = profileData;

    const result = await query(`
      UPDATE users 
      SET first_name = COALESCE($1, first_name),
          last_name = COALESCE($2, last_name),
          bio = COALESCE($3, bio),
          avatar_url = COALESCE($4, avatar_url),
          preferences = COALESCE($5, preferences)
      WHERE id = $6
      RETURNING id, username, email, first_name, last_name, role,
                is_active, email_verified, last_login, created_at,
                updated_at, preferences, avatar_url, bio
    `, [firstName, lastName, bio, avatarUrl, JSON.stringify(preferences), userId]);

    if (result.rows.length === 0) {
      throw new Error('User not found');
    }

    const user = result.rows[0];
    
    logger.audit('USER_PROFILE_UPDATED', {
      userId,
      changes: Object.keys(profileData)
    });

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      isActive: user.is_active,
      emailVerified: user.email_verified,
      lastLogin: user.last_login,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
      preferences: user.preferences || {},
      avatarUrl: user.avatar_url,
      bio: user.bio
    };
  } catch (error) {
    logger.error('Failed to update user profile:', error);
    throw error;
  }
}

/**
 * Create password reset token
 */
export async function createPasswordResetToken(userId, token, expiresAt) {
  try {
    await query(`
      UPDATE users 
      SET password_reset_token = $1, password_reset_expires = $2
      WHERE id = $3
    `, [token, expiresAt, userId]);

    logger.audit('PASSWORD_RESET_TOKEN_CREATED', { userId });
  } catch (error) {
    logger.error('Failed to create password reset token:', error);
    throw error;
  }
}

/**
 * Validate password reset token and return user
 */
export async function validatePasswordResetToken(token) {
  try {
    const result = await query(`
      SELECT id, username, email, first_name, last_name
      FROM users 
      WHERE password_reset_token = $1 
        AND password_reset_expires > NOW()
        AND is_active = true
    `, [token]);

    if (result.rows.length === 0) {
      return null;
    }

    const user = result.rows[0];
    
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name
    };
  } catch (error) {
    logger.error('Failed to validate password reset token:', error);
    throw error;
  }
}

/**
 * Get users with pagination
 */
export async function getUsers(options = {}) {
  try {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'desc',
      search = '',
      role = null,
      isActive = null
    } = options;

    const offset = (page - 1) * limit;
    const validSortFields = ['created_at', 'updated_at', 'username', 'email', 'last_login'];
    const sortField = validSortFields.includes(sortBy) ? sortBy : 'created_at';
    const order = ['asc', 'desc'].includes(sortOrder.toLowerCase()) ? sortOrder.toUpperCase() : 'DESC';

    let whereClause = 'WHERE 1=1';
    const params = [];
    let paramIndex = 1;

    if (search) {
      whereClause += ` AND (username ILIKE $${paramIndex} OR email ILIKE $${paramIndex} OR first_name ILIKE $${paramIndex} OR last_name ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    if (role) {
      whereClause += ` AND role = $${paramIndex}`;
      params.push(role);
      paramIndex++;
    }

    if (isActive !== null) {
      whereClause += ` AND is_active = $${paramIndex}`;
      params.push(isActive);
      paramIndex++;
    }

    // Get total count
    const countResult = await query(`
      SELECT COUNT(*) FROM users ${whereClause}
    `, params);

    const totalCount = parseInt(countResult.rows[0].count);

    // Get users
    const result = await query(`
      SELECT id, username, email, first_name, last_name, role,
             is_active, email_verified, last_login, created_at, updated_at
      FROM users ${whereClause}
      ORDER BY ${sortField} ${order}
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `, [...params, limit, offset]);

    const users = result.rows.map(user => ({
      id: user.id,
      username: user.username,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      isActive: user.is_active,
      emailVerified: user.email_verified,
      lastLogin: user.last_login,
      createdAt: user.created_at,
      updatedAt: user.updated_at
    }));

    return {
      users,
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
      currentPage: page,
      hasNext: offset + limit < totalCount,
      hasPrev: page > 1
    };
  } catch (error) {
    logger.error('Failed to get users:', error);
    throw error;
  }
}

/**
 * Delete user (soft delete by deactivating)
 */
export async function deleteUser(userId) {
  try {
    await transaction(async (client) => {
      // Soft delete by deactivating user
      await client.query(`
        UPDATE users 
        SET is_active = false, 
            email = email || '.deleted.' || extract(epoch from now()),
            username = username || '.deleted.' || extract(epoch from now())
        WHERE id = $1
      `, [userId]);

      // Invalidate all sessions
      await client.query(`
        UPDATE user_sessions SET is_active = false WHERE user_id = $1
      `, [userId]);

      // Note: We keep encrypted data for potential recovery
      // In a real scenario, you might want to schedule it for deletion after a grace period
    });

    logger.audit('USER_DELETED', { userId });
  } catch (error) {
    logger.error('Failed to delete user:', error);
    throw error;
  }
}

/**
 * Store encrypted sensitive data for user
 */
export async function storeUserEncryptedData(userId, dataType, data) {
  try {
    const encryptedData = encryptField(data);
    
    await query(`
      INSERT INTO user_encrypted_data (user_id, data_type, encrypted_data)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, data_type)
      DO UPDATE SET encrypted_data = $3, updated_at = NOW()
    `, [userId, dataType, JSON.stringify(encryptedData)]);

    logger.audit('USER_ENCRYPTED_DATA_STORED', {
      userId,
      dataType
    });
  } catch (error) {
    logger.error('Failed to store encrypted user data:', error);
    throw error;
  }
}

/**
 * Retrieve encrypted sensitive data for user
 */
export async function getUserEncryptedData(userId, dataType) {
  try {
    const result = await query(`
      SELECT encrypted_data FROM user_encrypted_data
      WHERE user_id = $1 AND data_type = $2
    `, [userId, dataType]);

    if (result.rows.length === 0) {
      return null;
    }

    const encryptedData = result.rows[0].encrypted_data;
    const decryptedData = decryptField(encryptedData);

    return decryptedData;
  } catch (error) {
    logger.error('Failed to get encrypted user data:', error);
    throw error;
  }
}

/**
 * Get user statistics
 */
export async function getUserStats(userId) {
  try {
    const result = await query(`
      SELECT 
        COUNT(DISTINCT up.stage_id) as stages_completed,
        COALESCE(SUM(up.time_spent), 0) as total_time_spent,
        COUNT(up.id) as total_sessions,
        AVG(up.rating) as average_rating,
        MAX(up.created_at) as last_session
      FROM user_progress up
      WHERE up.user_id = $1 AND up.completed_at IS NOT NULL
    `, [userId]);

    const stats = result.rows[0];

    return {
      stagesCompleted: parseInt(stats.stages_completed || 0),
      totalTimeSpent: parseInt(stats.total_time_spent || 0),
      totalSessions: parseInt(stats.total_sessions || 0),
      averageRating: stats.average_rating ? parseFloat(stats.average_rating).toFixed(1) : null,
      lastSession: stats.last_session
    };
  } catch (error) {
    logger.error('Failed to get user statistics:', error);
    throw error;
  }
}

export default {
  createUser,
  getUserById,
  getUserByEmail,
  getUserByUsername,
  updateUserLastLogin,
  updateUserLastSeen,
  updateUserPassword,
  updateUserProfile,
  createPasswordResetToken,
  validatePasswordResetToken,
  getUsers,
  deleteUser,
  storeUserEncryptedData,
  getUserEncryptedData,
  getUserStats
};
