// Auth Service Implementation
// Handles user registration, login, and refresh token rotation
// Uses adapter pattern for database abstraction

import { z } from 'zod';
import { hashPassword, verifyPassword } from '../core/crypto.js';
import { signAccessToken, signRefreshToken, verifyJWT } from '../core/crypto.js';

// Zod validation schemas
const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1, 'Password is required'),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(10, 'Refresh token is required'),
});

/**
 * AuthService class
 * Orchestrates authentication flows using adapter pattern
 */
export class AuthService {
  /**
   * Create AuthService instance
   * @param {BaseAdapter} adapter - Database adapter implementation
   */
  constructor(adapter) {
    this.adapter = adapter;
  }

  /**
   * Register a new user
   * @param {string} email - User's email address
   * @param {string} password - User's password
   * @returns {Promise<{success: true, userId: string}>} Success response
   * @throws {Error} Validation errors or registration failures
   */
  async register(email, password) {
    // Validate input
    const validated = registerSchema.safeParse({ email, password });
    if (!validated.success) {
      throw new Error(validated.error.issues[0].message);
    }

    // Check if user already exists
    const existingUser = await this.adapter.findUserByEmail(email);
    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const user = await this.adapter.createUser({
      email: validated.data.email,
      hashedPassword: hashedPassword,
    });

    return {
      success: true,
      userId: user.id,
    };
  }

  /**
   * Login user and issue token pair
   * @param {string} email - User's email address
   * @param {string} password - User's password
   * @returns {Promise<{success: true, accessToken: string, refreshToken: string}>} Token pair
   * @throws {Error} Generic "Invalid credentials" for security
   */
  async login(email, password) {
    // Validate input
    const validated = loginSchema.safeParse({ email, password });
    if (!validated.success) {
      throw new Error(validated.error.issues[0].message);
    }

    // Find user by email
    const user = await this.adapter.findUserByEmail(validated.data.email);

    // Always perform password verification for timing safety
    // Use a dummy hash if user doesn't exist to maintain consistent timing
    const hashToCheck = user ? user.hashedPassword : '$argon2id$v=19$m=65536,t=3,p=4$ltv4rLoGLpCul8wO1xwJlQ$vfkMCoi/vx7JJF0BBMrzxR/RuGzzv9i4M4o1vYfDfqY';
    const passwordValid = await verifyPassword(hashToCheck, validated.data.password);

    // Check both user existence and password validity
    if (!user || !passwordValid) {
      throw new Error('Invalid credentials');
    }

    // Generate token pair
    const accessToken = await signAccessToken({ userId: user.id, role: user.role });
    const refreshToken = await signRefreshToken({ userId: user.id });

    // Save refresh token
    await this.adapter.saveRefreshToken(
      user.id,
      refreshToken,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days from now
    );

    return {
      success: true,
      accessToken,
      refreshToken,
    };
  }

  /**
   * Refresh access token using refresh token
   * Implements automatic breach detection
   * @param {string} refreshToken - Valid refresh token
   * @returns {Promise<{success: true, accessToken: string, refreshToken: string}>} New token pair
   * @throws {Error} If token is invalid or revoked
   */
  async refresh(refreshToken) {
    // Validate input
    const validated = refreshSchema.safeParse({ refreshToken });
    if (!validated.success) {
      throw new Error(validated.error.issues[0].message);
    }

    // Verify JWT signature and extract payload
    let payload;
    try {
      payload = await verifyJWT(validated.data.refreshToken, 'refresh');
    } catch (error) {
      throw new Error('Invalid refresh token');
    }

    // Check if token is revoked or expired
    const isValid = await this.adapter.isRefreshTokenValid(validated.data.refreshToken);
    if (!isValid) {
      // Automatic breach detection: revoke all tokens for this user
      await this.adapter.revokeAllUserSessions(payload.userId);
      throw new Error('Session revoked - please login again');
    }

    // Revoke old refresh token (token rotation)
    await this.adapter.revokeRefreshToken(validated.data.refreshToken);

    // Issue new token pair
    const newAccessToken = await signAccessToken({ 
      userId: payload.userId, 
      role: payload.role || 'user' 
    });
    const newRefreshToken = await signRefreshToken({ userId: payload.userId });

    // Save new refresh token
    await this.adapter.saveRefreshToken(
      payload.userId,
      newRefreshToken,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days from now
    );

    return {
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }
}

export default AuthService;
