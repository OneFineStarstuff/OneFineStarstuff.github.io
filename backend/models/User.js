/**
 * User Model
 * Handles user CRUD operations with encrypted sensitive data
 */

import { query } from '../config/database.js'

function mapUser (user, includePassword = false) {
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
  }
}

export async function createUser (userData) {
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
  } = userData

  const result = await query(
    'INSERT INTO users (username, email, password_hash, encryption_salt, first_name, last_name, is_active, email_verified, role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
    [username, email, password, encryptionSalt, firstName, lastName, isActive, emailVerified, role]
  )
  return mapUser(result.rows[0])
}

export async function getUserByEmail (email, includePassword = false) {
  const result = await query('SELECT * FROM users WHERE email = $1', [email])
  if (result.rows.length === 0) return null
  return mapUser(result.rows[0], includePassword)
}

export async function getUserById (id) {
  const result = await query('SELECT * FROM users WHERE id = $1', [id])
  if (result.rows.length === 0) return null
  return mapUser(result.rows[0])
}

export async function updateUserProfile (id, profileData) {
  const { firstName, lastName, bio, avatarUrl, preferences } = profileData
  const result = await query(
    'UPDATE users SET first_name = $1, last_name = $2, bio = $3, avatar_url = $4, preferences = $5, updated_at = NOW() WHERE id = $6 RETURNING *',
    [firstName, lastName, bio, avatarUrl, preferences, id]
  )
  if (result.rows.length === 0) return null
  return mapUser(result.rows[0])
}
