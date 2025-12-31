import { BaseAdapter, userSchema, refreshTokenSchema } from './base.js';

/**
 * In-memory adapter implementation for testing
 * Uses simple JavaScript objects to store data
 */
export class MemoryAdapter extends BaseAdapter {
  #users = new Map(); // email -> user object
  #refreshTokens = new Map(); // token -> { userId, expiresAt }
  #revokedTokens = new Set(); // token -> boolean

  /**
   * Finds a user by email
   * @param {string} email - The email to search for
   * @returns {Promise<object|null>} The user object or null if not found
   */
  async findUserByEmail(email) {
    if (typeof email !== 'string') {
      throw new Error('Email must be a string');
    }
    return this.#users.get(email) || null;
  }

  /**
   * Creates a new user
   * @param {object} userData - User data including email and hashedPassword
   * @returns {Promise<object>} The created user object
   */
  async createUser(userData) {
    // Validate input
    const validated = userSchema.parse(userData);
    
    if (this.#users.has(validated.email)) {
      throw new Error('User with this email already exists');
    }
    
    const user = {
      id: crypto.randomUUID(),
      email: validated.email,
      hashedPassword: validated.hashedPassword,
      role: validated.role,
      createdAt: new Date()
    };
    
    this.#users.set(validated.email, user);
    return user;
  }

  /**
   * Saves a refresh token for a user
   * @param {string} userId - The user ID
   * @param {string} token - The refresh token
   * @param {Date} expiresAt - The expiration date
   * @returns {Promise<void>}
   */
  async saveRefreshToken(userId, token, expiresAt) {
    if (typeof userId !== 'string' || typeof token !== 'string' || !(expiresAt instanceof Date)) {
      throw new Error('Invalid parameters');
    }
    
    // Validate token format
    if (token.length < 10) {
      throw new Error('Token too short');
    }
    
    this.#refreshTokens.set(token, { userId, expiresAt });
    this.#revokedTokens.delete(token);
  }

  /**
   * Checks if a refresh token is valid (not revoked and not expired)
   * @param {string} token - The refresh token to check
   * @returns {Promise<boolean>} True if the token is valid
   */
  async isRefreshTokenValid(token) {
    if (typeof token !== 'string') {
      throw new Error('Token must be a string');
    }
    
    const tokenData = this.#refreshTokens.get(token);
    
    if (!tokenData) {
      return false;
    }
    
    // Check if revoked
    if (this.#revokedTokens.has(token)) {
      return false;
    }
    
    // Check if expired
    if (tokenData.expiresAt < new Date()) {
      return false;
    }
    
    return true;
  }

  /**
   * Revokes a refresh token
   * @param {string} token - The refresh token to revoke
   * @returns {Promise<void>}
   */
  async revokeRefreshToken(token) {
    if (typeof token !== 'string') {
      throw new Error('Token must be a string');
    }
    this.#revokedTokens.add(token);
  }

  /**
   * Revokes all refresh tokens for a user (for security incidents)
   * @param {string} userId - The user ID
   * @returns {Promise<void>}
   */
  async revokeAllUserSessions(userId) {
    if (typeof userId !== 'string') {
      throw new Error('User ID must be a string');
    }
    
    // Find all tokens for this user and revoke them
    for (const [token, tokenData] of this.#refreshTokens.entries()) {
      if (tokenData.userId === userId) {
        this.#revokedTokens.add(token);
      }
    }
  }

  /**
   * Helper method to clear all data (for testing)
   * @returns {Promise<void>}
   */
  async clear() {
    this.#users.clear();
    this.#refreshTokens.clear();
    this.#revokedTokens.clear();
  }

  /**
   * Helper method to get user by ID (not part of BaseAdapter contract)
   * @param {string} userId - The user ID
   * @returns {Promise<object|null>} The user object or null if not found
   */
  async findUserById(userId) {
    if (typeof userId !== 'string') {
      throw new Error('User ID must be a string');
    }
    
    for (const user of this.#users.values()) {
      if (user.id === userId) {
        return user;
      }
    }
    return null;
  }
}

// Export a singleton instance for convenience
export const memoryAdapter = new MemoryAdapter();