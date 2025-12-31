import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { AuthService } from '../src/services/auth-service.js';
import { MemoryAdapter } from '../src/adapters/memory.js';
import { hashPassword } from '../src/core/crypto.js';

// Mock environment variables
const originalEnv = process.env;

beforeEach(async () => {
  jest.resetModules();
  process.env = { ...originalEnv };
  process.env.ACCESS_TOKEN_SECRET = 'test_access_secret_32_characters_long';
  process.env.REFRESH_TOKEN_SECRET = 'test_refresh_secret_32_characters_long';
  
  // Clear adapter state
  const adapter = new MemoryAdapter();
  adapter.clear();
  
  // Create test user
  const testUser = {
    id: 'test-user-id',
    email: 'test@example.com',
    hashedPassword: await hashPassword('password123'),
    role: 'user'
  };
  await adapter.createUser(testUser);
  
  // Save a valid refresh token for the test user
  await adapter.saveRefreshToken(
    testUser.id,
    'valid-refresh-token-abc123',
    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  );
  
  // Store adapter in a global variable so tests can use it
  global.testAdapter = adapter;
});

afterAll(() => {
  process.env = originalEnv;
});

describe('AuthService - Registration', () => {
  it('should successfully register a new user', async () => {
    const adapter = new MemoryAdapter();
    adapter.clear();
    const service = new AuthService(adapter);
    
    const result = await service.register('newuser@example.com', 'securePassword123');
    
    expect(result.success).toBe(true);
    expect(result.userId).toBeDefined();
    expect(typeof result.userId).toBe('string');
    
    // Verify user was created in adapter
    const user = await adapter.findUserByEmail('newuser@example.com');
    expect(user).toBeDefined();
    expect(user.email).toBe('newuser@example.com');
  });

  it('should throw error for duplicate email', async () => {
    const adapter = new MemoryAdapter();
    const service = new AuthService(adapter);
    
    // First registration should succeed
    await service.register('duplicate@example.com', 'password123');
    
    // Second registration should fail
    await expect(service.register('duplicate@example.com', 'password456'))
      .rejects
      .toThrow('User already exists');
  });

  it('should throw error for invalid email format', async () => {
    const adapter = new MemoryAdapter();
    const service = new AuthService(adapter);
    
    await expect(service.register('invalid-email', 'password123'))
      .rejects
      .toThrow();
  });

  it('should throw error for short password', async () => {
    const adapter = new MemoryAdapter();
    const service = new AuthService(adapter);
    
    await expect(service.register('user@example.com', 'short'))
      .rejects
      .toThrow('Password must be at least 8 characters');
  });
});

describe('AuthService - Login', () => {
  it('should successfully login with correct credentials', async () => {
    const service = new AuthService(global.testAdapter);
    
    const result = await service.login('test@example.com', 'password123');
    
    expect(result.success).toBe(true);
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
    expect(typeof result.accessToken).toBe('string');
    expect(typeof result.refreshToken).toBe('string');
    
    // Verify refresh token was saved
    const isValid = await global.testAdapter.isRefreshTokenValid(result.refreshToken);
    expect(isValid).toBe(true);
  });

  it('should throw error for invalid credentials (wrong password)', async () => {
    const service = new AuthService(global.testAdapter);
    
    await expect(service.login('test@example.com', 'wrongpassword'))
      .rejects
      .toThrow('Invalid credentials');
  });

  it('should throw error for invalid credentials (non-existent user)', async () => {
    const service = new AuthService(global.testAdapter);
    
    await expect(service.login('nonexistent@example.com', 'password123'))
      .rejects
      .toThrow('Invalid credentials');
  });

  it('should maintain timing safety for invalid credentials', async () => {
    const service = new AuthService(global.testAdapter);
    
    let startTime = Date.now();
    
    // Test with non-existent user
    try {
      await service.login('nonexistent@example.com', 'password123');
    } catch (error) {
      // Expected to fail
    }
    const time1 = Date.now() - startTime;
    
    // Test with existing user but wrong password
    startTime = Date.now();
    try {
      await service.login('test@example.com', 'wrongpassword');
    } catch (error) {
      // Expected to fail
    }
    const time2 = Date.now() - startTime;
    
    // Times should be similar (within 50ms tolerance)
    expect(Math.abs(time1 - time2)).toBeLessThan(50);
  });
});

describe('AuthService - Token Rotation', () => {
  it('should successfully rotate tokens', async () => {
    const service = new AuthService(global.testAdapter);
    
    // First login to get initial tokens
    const loginResult = await service.login('test@example.com', 'password123');
    const oldRefreshToken = loginResult.refreshToken;
    
    // Rotate tokens
    const refreshResult = await service.refresh(oldRefreshToken);
    
    expect(refreshResult.success).toBe(true);
    expect(refreshResult.accessToken).toBeDefined();
    expect(refreshResult.refreshToken).toBeDefined();
    expect(refreshResult.accessToken).not.toBe(oldRefreshToken);
    expect(refreshResult.refreshToken).not.toBe(oldRefreshToken);
    
    // Verify old refresh token is revoked
    const isOldTokenValid = await global.testAdapter.isRefreshTokenValid(oldRefreshToken);
    expect(isOldTokenValid).toBe(false);
    
    // Verify new refresh token is valid
    const isNewTokenValid = await global.testAdapter.isRefreshTokenValid(refreshResult.refreshToken);
    expect(isNewTokenValid).toBe(true);
  });

  it('should throw error for invalid refresh token', async () => {
    const service = new AuthService(global.testAdapter);
    
    await expect(service.refresh('invalid-token'))
      .rejects
      .toThrow('Invalid refresh token');
  });

  it('should throw error for revoked refresh token', async () => {
    const service = new AuthService(global.testAdapter);
    
    // Login to get a token
    const loginResult = await service.login('test@example.com', 'password123');
    const refreshToken = loginResult.refreshToken;
    
    // Revoke the token
    await global.testAdapter.revokeRefreshToken(refreshToken);
    
    // Try to use revoked token
    await expect(service.refresh(refreshToken))
      .rejects
      .toThrow('Session revoked - please login again');
  });

  it('should automatically revoke all sessions when refresh token is reused', async () => {
    const service = new AuthService(global.testAdapter);
    
    // Login to get initial tokens
    const loginResult = await service.login('test@example.com', 'password123');
    const firstRefreshToken = loginResult.refreshToken;
    
    // Rotate once
    const refreshResult1 = await service.refresh(firstRefreshToken);
    const secondRefreshToken = refreshResult1.refreshToken;
    
    // Rotate again
    const refreshResult2 = await service.refresh(secondRefreshToken);
    const thirdRefreshToken = refreshResult2.refreshToken;
    
    // Now try to use the first refresh token (which was revoked)
    await expect(service.refresh(firstRefreshToken))
      .rejects
      .toThrow('Session revoked - please login again');
    
    // Verify all tokens for this user are now revoked
    const isFirstValid = await global.testAdapter.isRefreshTokenValid(firstRefreshToken);
    const isSecondValid = await global.testAdapter.isRefreshTokenValid(secondRefreshToken);
    const isThirdValid = await global.testAdapter.isRefreshTokenValid(thirdRefreshToken);
    
    expect(isFirstValid).toBe(false);
    expect(isSecondValid).toBe(false);
    expect(isThirdValid).toBe(false);
  });

  it('should throw error for expired refresh token', async () => {
    const service = new AuthService(global.testAdapter);
    
    // Create a user
    await service.register('expired@example.com', 'password123');
    
    // Login to get tokens
    const loginResult = await service.login('expired@example.com', 'password123');
    const refreshToken = loginResult.refreshToken;
    
    // Manually revoke the token to simulate expiration
    await global.testAdapter.revokeRefreshToken(refreshToken);
    
    // Try to use expired token
    await expect(service.refresh(refreshToken))
      .rejects
      .toThrow('Session revoked - please login again');
  });

  it('should throw error for short refresh token', async () => {
    const service = new AuthService(global.testAdapter);
    
    await expect(service.refresh('short'))
      .rejects
      .toThrow('Refresh token is required');
  });
});

describe('AuthService - Integration with MemoryAdapter', () => {
  it('should maintain proper state across multiple operations', async () => {
    const adapter = new MemoryAdapter();
    adapter.clear();
    const service = new AuthService(adapter);
    
    // Register multiple users
    const user1 = await service.register('user1@example.com', 'password123');
    const user2 = await service.register('user2@example.com', 'password456');
    
    // Login both users
    const login1 = await service.login('user1@example.com', 'password123');
    const login2 = await service.login('user2@example.com', 'password456');
    
    // Verify tokens are saved
    expect(await adapter.isRefreshTokenValid(login1.refreshToken)).toBe(true);
    expect(await adapter.isRefreshTokenValid(login2.refreshToken)).toBe(true);
    
    // Rotate user1's token
    const refresh1 = await service.refresh(login1.refreshToken);
    
    // Verify user1's old token is revoked but user2's token is still valid
    expect(await adapter.isRefreshTokenValid(login1.refreshToken)).toBe(false);
    expect(await adapter.isRefreshTokenValid(login2.refreshToken)).toBe(true);
    expect(await adapter.isRefreshTokenValid(refresh1.refreshToken)).toBe(true);
  });
});