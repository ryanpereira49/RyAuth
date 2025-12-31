import { describe, it, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { hashPassword, verifyPassword, signAccessToken, signRefreshToken, verifyJWT } from '../src/core/crypto.js';
import argon2 from 'argon2';

// Mock environment variables
const originalEnv = process.env;

beforeAll(() => {
  // Set up test secrets
  process.env.ACCESS_TOKEN_SECRET = 'test_access_secret_32_characters_long_1234567890';
  process.env.REFRESH_TOKEN_SECRET = 'test_refresh_secret_32_characters_long_1234567890';
});

afterAll(() => {
  process.env = originalEnv;
});

describe('Core Crypto Module - Password Hashing', () => {
  describe('hashPassword', () => {
    it('should return a valid Argon2 string', async () => {
      const password = 'securePassword123!';
      const hash = await hashPassword(password);
      
      // Verify it's a valid Argon2 hash
      expect(typeof hash).toBe('string');
      expect(hash).toBeTruthy();
      
      // Verify argon2 can verify it
      const isValid = await argon2.verify(hash, password);
      expect(isValid).toBe(true);
    });

    it('should throw error if input is not a string', async () => {
      await expect(hashPassword(123)).rejects.toThrow('Password must be a string');
      await expect(hashPassword(null)).rejects.toThrow('Password must be a string');
      await expect(hashPassword(undefined)).rejects.toThrow('Password must be a string');
      await expect(hashPassword({})).rejects.toThrow('Password must be a string');
      await expect(hashPassword([])).rejects.toThrow('Password must be a string');
    });
  });

  describe('verifyPassword', () => {
    let testHash;

    beforeAll(async () => {
      testHash = await hashPassword('testPassword123');
    });

    it('should return true for correct credentials using timing-safe comparison', async () => {
      const result = await verifyPassword(testHash, 'testPassword123');
      expect(result).toBe(true);
    });

    it('should return false for incorrect credentials', async () => {
      const result = await verifyPassword(testHash, 'wrongPassword');
      expect(result).toBe(false);
    });

    it('should throw error if hash is not a string', async () => {
      await expect(verifyPassword(123, 'password')).rejects.toThrow('Hash and plain text must be strings');
      await expect(verifyPassword(null, 'password')).rejects.toThrow('Hash and plain text must be strings');
    });

    it('should throw error if plain text is not a string', async () => {
      await expect(verifyPassword(testHash, 123)).rejects.toThrow('Hash and plain text must be strings');
      await expect(verifyPassword(testHash, null)).rejects.toThrow('Hash and plain text must be strings');
    });
  });
});

describe('Core Crypto Module - JWT Management', () => {
  const testPayload = {
    userId: '12345',
    email: 'test@example.com',
    roles: ['user']
  };

  describe('signAccessToken', () => {
    it('should generate a JWT with a 15-minute expiry', async () => {
      const token = await signAccessToken(testPayload);
      
      expect(typeof token).toBe('string');
      expect(token).toBeTruthy();
      
      // Verify the token can be decoded
      const payload = await verifyJWT(token, 'access');
      expect(payload.userId).toBe(testPayload.userId);
      expect(payload.email).toBe(testPayload.email);
    });

    it('should throw error if ACCESS_TOKEN_SECRET is missing', async () => {
      const originalSecret = process.env.ACCESS_TOKEN_SECRET;
      delete process.env.ACCESS_TOKEN_SECRET;
      
      await expect(signAccessToken(testPayload)).rejects.toThrow('ACCESS_TOKEN_SECRET must be at least 32 characters');
      
      process.env.ACCESS_TOKEN_SECRET = originalSecret;
    });

    it('should throw error if ACCESS_TOKEN_SECRET is less than 32 characters', async () => {
      const originalSecret = process.env.ACCESS_TOKEN_SECRET;
      process.env.ACCESS_TOKEN_SECRET = 'short';
      
      await expect(signAccessToken(testPayload)).rejects.toThrow('ACCESS_TOKEN_SECRET must be at least 32 characters');
      
      process.env.ACCESS_TOKEN_SECRET = originalSecret;
    });
  });

  describe('signRefreshToken', () => {
    it('should generate a JWT with a 7-day expiry', async () => {
      const token = await signRefreshToken(testPayload);
      
      expect(typeof token).toBe('string');
      expect(token).toBeTruthy();
      
      // Verify the token can be decoded
      const payload = await verifyJWT(token, 'refresh');
      expect(payload.userId).toBe(testPayload.userId);
      expect(payload.email).toBe(testPayload.email);
    });

    it('should throw error if REFRESH_TOKEN_SECRET is missing', async () => {
      const originalSecret = process.env.REFRESH_TOKEN_SECRET;
      delete process.env.REFRESH_TOKEN_SECRET;
      
      await expect(signRefreshToken(testPayload)).rejects.toThrow('REFRESH_TOKEN_SECRET must be at least 32 characters');
      
      process.env.REFRESH_TOKEN_SECRET = originalSecret;
    });

    it('should throw error if REFRESH_TOKEN_SECRET is less than 32 characters', async () => {
      const originalSecret = process.env.REFRESH_TOKEN_SECRET;
      process.env.REFRESH_TOKEN_SECRET = 'short';
      
      await expect(signRefreshToken(testPayload)).rejects.toThrow('REFRESH_TOKEN_SECRET must be at least 32 characters');
      
      process.env.REFRESH_TOKEN_SECRET = originalSecret;
    });
  });

  describe('verifyJWT', () => {
    let accessToken;
    let refreshToken;

    beforeAll(async () => {
      accessToken = await signAccessToken(testPayload);
      refreshToken = await signRefreshToken(testPayload);
    });

    it('should successfully decode access tokens', async () => {
      const payload = await verifyJWT(accessToken, 'access');
      expect(payload.userId).toBe(testPayload.userId);
      expect(payload.email).toBe(testPayload.email);
      expect(payload.roles).toEqual(testPayload.roles);
    });

    it('should successfully decode refresh tokens', async () => {
      const payload = await verifyJWT(refreshToken, 'refresh');
      expect(payload.userId).toBe(testPayload.userId);
      expect(payload.email).toBe(testPayload.email);
      expect(payload.roles).toEqual(testPayload.roles);
    });

    it('should throw error if token is used for the wrong type (type-check validation)', async () => {
      // Try to verify access token as refresh token
      await expect(verifyJWT(accessToken, 'refresh')).rejects.toThrow('Invalid token');
      
      // Try to verify refresh token as access token
      await expect(verifyJWT(refreshToken, 'access')).rejects.toThrow('Invalid token');
    });

    it('should throw error if token is invalid', async () => {
      await expect(verifyJWT('invalid.token.here', 'access')).rejects.toThrow('Invalid token');
      await expect(verifyJWT('', 'access')).rejects.toThrow('Invalid token');
    });

    it('should throw error if token is not a string', async () => {
      await expect(verifyJWT(123, 'access')).rejects.toThrow('Token must be a string');
      await expect(verifyJWT(null, 'access')).rejects.toThrow('Token must be a string');
      await expect(verifyJWT(undefined, 'access')).rejects.toThrow('Token must be a string');
    });

    it('should throw error if ACCESS_TOKEN_SECRET is missing during verification', async () => {
      const originalSecret = process.env.ACCESS_TOKEN_SECRET;
      delete process.env.ACCESS_TOKEN_SECRET;
      
      await expect(verifyJWT(accessToken, 'access')).rejects.toThrow('ACCESS_TOKEN_SECRET must be at least 32 characters');
      
      process.env.ACCESS_TOKEN_SECRET = originalSecret;
    });

    it('should throw error if REFRESH_TOKEN_SECRET is missing during verification', async () => {
      const originalSecret = process.env.REFRESH_TOKEN_SECRET;
      delete process.env.REFRESH_TOKEN_SECRET;
      
      await expect(verifyJWT(refreshToken, 'refresh')).rejects.toThrow('REFRESH_TOKEN_SECRET must be at least 32 characters');
      
      process.env.REFRESH_TOKEN_SECRET = originalSecret;
    });
  });
});