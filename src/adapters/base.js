import { z } from 'zod';

/**
 * BaseAdapter class defining the contract for database operations
 * This is an abstract class that concrete adapters must implement
 */
export class BaseAdapter {
  /**
   * Finds a user by email
   * @param {string} email - The email to search for
   * @returns {Promise<object|null>} The user object or null if not found
   */
  async findUserByEmail(email) {
    throw new Error('Method findUserByEmail() must be implemented');
  }

  /**
   * Creates a new user
   * @param {object} userData - User data including email and hashedPassword
   * @returns {Promise<object>} The created user object
   */
  async createUser(userData) {
    throw new Error('Method createUser() must be implemented');
  }

  /**
   * Saves a refresh token for a user
   * @param {string} userId - The user ID
   * @param {string} token - The refresh token
   * @param {Date} expiresAt - The expiration date
   * @returns {Promise<void>}
   */
  async saveRefreshToken(userId, token, expiresAt) {
    throw new Error('Method saveRefreshToken() must be implemented');
  }

  /**
   * Checks if a refresh token is valid (not revoked and not expired)
   * @param {string} token - The refresh token to check
   * @returns {Promise<boolean>} True if the token is valid
   */
  async isRefreshTokenValid(token) {
    throw new Error('Method isRefreshTokenValid() must be implemented');
  }

  /**
   * Revokes a refresh token
   * @param {string} token - The refresh token to revoke
   * @returns {Promise<void>}
   */
  async revokeRefreshToken(token) {
    throw new Error('Method revokeRefreshToken() must be implemented');
  }

  /**
   * Revokes all refresh tokens for a user (for security incidents)
   * @param {string} userId - The user ID
   * @returns {Promise<void>}
   */
  async revokeAllUserSessions(userId) {
    throw new Error('Method revokeAllUserSessions() must be implemented');
  }
}

/**
 * User schema for validation
 */
export const userSchema = z.object({
  email: z.string().email(),
  hashedPassword: z.string(),
  role: z.string().optional().default('user')
});

/**
 * Refresh token schema for validation
 */
export const refreshTokenSchema = z.object({
  userId: z.string(),
  token: z.string(),
  expiresAt: z.date()
});