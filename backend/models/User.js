/**
 * User Model
 * Handles user CRUD operations with encrypted sensitive data
 */

import { query, transaction } from '../config/database.js';
import { encryptField, decryptField } from '../utils/encryption.js';
import logger from '../utils/logger.js';
import crypto from 'crypto';

/**
 * Create a new user.
 *
 * This function takes user data, including username, email, and password, and inserts a new user record into the database.
 * It handles default values for isActive, emailVerified, and role. After successfully creating the user, it logs the creation
 * event and returns the newly created user's information. In case of an error, it logs the error and rethrows it.
 *
 * @param {Object} userData - The data for the new user.
 * @param {string} userData.username - The username of the new user.
 * @param {string} userData.email - The email address of the new user.
 * @param {string} userData.password - The password for the new user.
 * @param {string} userData.firstName - The first name of the new user.
 * @param {string} userData.lastName - The last name of the new user.
 * @param {string} userData.encryptionSalt - The salt used for password encryption.
 * @param {boolean} [userData.isActive=true] - Indicates if the user is active.
 * @param {boolean} [userData.emailVerified=false] - Indicates if the user's email is verified.
 * @param {string} [userData.role='user'] - The role assigned to the new user.
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
 * Get user details by their ID.
 *
 * This function retrieves user information from the database based on the provided userId.
 * It allows for an optional inclusion of the user's password hash. The retrieved data is then
 * transformed from snake_case to camelCase for consistency in the API response. If no user is found,
 * it returns null. Any errors during the query process are logged and rethrown.
 *
 * @param userId - The ID of the user to retrieve.
 * @param includePassword - A boolean indicating whether to include the user's password hash in the response.
 * @returns An object containing user details in camelCase format, or null if no user is found.
 * @throws Error If there is an issue with the database query.
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
 * Get user details by their email address.
 *
 * This function queries the database for a user with the specified email. It allows for the inclusion of the user's password hash based on the includePassword parameter. If no user is found, it returns null. The function also handles errors by logging them and rethrowing the error for further handling.
 *
 * @param email - The email address of the user to retrieve.
 * @param includePassword - A boolean indicating whether to include the user's password hash in the returned object.
 * @returns An object containing user details, or null if no user is found.
 * @throws Error If there is an issue querying the database.
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
 * Get user by username.
 *
 * This function retrieves a user from the database based on the provided username. It executes a SQL query to fetch user details, including id, email, and role. If no user is found, it returns null. In case of an error during the query execution, it logs the error and rethrows it for further handling.
 *
 * @param {string} username - The username of the user to retrieve.
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
 * Update the last login timestamp for a user.
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
 * Update user last seen timestamp in the database.
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
 * Update user password and encryption salt.
 *
 * This function updates the user's password hash and encryption salt in the database. It also clears all encrypted user data, as the previous data becomes unreadable with the new salt. Additionally, it invalidates all active user sessions to ensure security. The operation is performed within a transaction to maintain data integrity, and any errors during the process are logged for auditing purposes.
 *
 * @param {string} userId - The ID of the user whose password is being updated.
 * @param {string} newPasswordHash - The new password hash to be set for the user.
 * @param {string} newEncryptionSalt - The new encryption salt to be set for the user.
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
 * Update user profile.
 *
 * This function updates the user's profile information in the database based on the provided userId and profileData.
 * It uses a SQL query to update fields such as first name, last name, bio, avatar URL, and preferences,
 * while ensuring that only non-null values are updated. If the user is not found, an error is thrown.
 * Additionally, it logs the update action and returns the updated user information.
 *
 * @param {string} userId - The ID of the user whose profile is to be updated.
 * @param {Object} profileData - The new profile data for the user.
 * @param {string} profileData.firstName - The user's first name.
 * @param {string} profileData.lastName - The user's last name.
 * @param {string} profileData.bio - The user's biography.
 * @param {string} profileData.avatarUrl - The URL of the user's avatar.
 * @param {Object} profileData.preferences - The user's preferences.
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
 * Create a password reset token for a user.
 *
 * This function updates the user's record in the database with a new password reset token and its expiration time.
 * It logs an audit message upon successful creation and handles any errors that occur during the database update,
 * logging the error details before rethrowing the error.
 *
 * @param {string} userId - The ID of the user for whom the password reset token is being created.
 * @param {string} token - The password reset token to be set for the user.
 * @param {Date} expiresAt - The expiration date and time for the password reset token.
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
 * Validate the password reset token and return user information.
 *
 * This function queries the database to check if the provided password reset token is valid
 * and has not expired. It retrieves the user's details if the token is valid and the user is active.
 * If the token is invalid or expired, it returns null. In case of an error during the query,
 * it logs the error and rethrows it.
 *
 * @param {string} token - The password reset token to validate.
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
 * Get users with pagination and filtering options.
 *
 * This function retrieves a paginated list of users from the database based on the provided options.
 * It constructs a dynamic SQL query with filters for search, role, and active status, and returns
 * the user data along with pagination information such as total count, total pages, and current page.
 *
 * @param options - An object containing pagination and filtering options.
 * @param options.page - The page number to retrieve (default is 1).
 * @param options.limit - The number of users per page (default is 20).
 * @param options.sortBy - The field to sort by (default is 'created_at').
 * @param options.sortOrder - The order of sorting (default is 'desc').
 * @param options.search - A search term to filter users by username or email.
 * @param options.role - A specific role to filter users.
 * @param options.isActive - A boolean to filter users by active status.
 * @returns An object containing the list of users, total count, total pages, current page,
 *          and flags indicating if there are next or previous pages.
 * @throws Error If the query fails to execute.
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
 * Delete user (soft delete by deactivating).
 *
 * This function performs a soft delete of a user by deactivating their account and updating their email and username
 * to indicate deletion. It also invalidates all active sessions associated with the user. The function is wrapped in a
 * transaction to ensure atomicity. In case of an error, it logs the failure and rethrows the error for further handling.
 *
 * @param {string} userId - The ID of the user to be deleted.
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
 * Store encrypted sensitive data for user.
 *
 * This function encrypts the provided data using the encryptField function and stores it in the user_encrypted_data table.
 * If a record for the userId and dataType already exists, it updates the encrypted_data and the updated_at timestamp.
 * The operation is wrapped in a try-catch block to handle any errors that may occur during the database operation.
 *
 * @param {string} userId - The unique identifier for the user.
 * @param {string} dataType - The type of data being stored.
 * @param {any} data - The sensitive data to be encrypted and stored.
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
 * Retrieve decrypted sensitive data for a user.
 *
 * This function queries the database for encrypted data associated with a specific userId and dataType.
 * If no data is found, it returns null. Otherwise, it decrypts the retrieved encrypted data using the
 * decryptField function and returns the decrypted result. Errors during the process are logged for debugging.
 *
 * @param {string} userId - The ID of the user whose data is being retrieved.
 * @param {string} dataType - The type of data to retrieve for the user.
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
 * Get user statistics for a specific user.
 *
 * This function retrieves various statistics related to a user's progress, including the number of stages completed, total time spent, total sessions, average rating, and the timestamp of the last session. It executes a SQL query to gather this data from the user_progress table, filtering by the provided userId. If an error occurs during the query execution, it logs the error and rethrows it.
 *
 * @param {number} userId - The ID of the user for whom to retrieve statistics.
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
