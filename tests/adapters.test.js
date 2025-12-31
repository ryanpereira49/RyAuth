import { BaseAdapter } from '../src/adapters/base.js';
import { MemoryAdapter } from '../src/adapters/memory.js';

describe('Data Adapters - BaseAdapter Contract', () => {
  let baseAdapter;

  beforeEach(() => {
    baseAdapter = new BaseAdapter();
  });

  describe('BaseAdapter - Interface Methods', () => {
    it('should throw "Not Implemented" error for findUserByEmail', async () => {
      await expect(baseAdapter.findUserByEmail('test@example.com'))
        .rejects
        .toThrow('Method findUserByEmail() must be implemented');
    });

    it('should throw "Not Implemented" error for createUser', async () => {
      await expect(baseAdapter.createUser({ email: 'test@example.com', hashedPassword: 'hash' }))
        .rejects
        .toThrow('Method createUser() must be implemented');
    });

    it('should throw "Not Implemented" error for saveRefreshToken', async () => {
      await expect(baseAdapter.saveRefreshToken('user123', 'token123', new Date()))
        .rejects
        .toThrow('Method saveRefreshToken() must be implemented');
    });

    it('should throw "Not Implemented" error for isRefreshTokenValid', async () => {
      await expect(baseAdapter.isRefreshTokenValid('token123'))
        .rejects
        .toThrow('Method isRefreshTokenValid() must be implemented');
    });

    it('should throw "Not Implemented" error for revokeRefreshToken', async () => {
      await expect(baseAdapter.revokeRefreshToken('token123'))
        .rejects
        .toThrow('Method revokeRefreshToken() must be implemented');
    });

    it('should throw "Not Implemented" error for revokeAllUserSessions', async () => {
      await expect(baseAdapter.revokeAllUserSessions('user123'))
        .rejects
        .toThrow('Method revokeAllUserSessions() must be implemented');
    });
  });
});

describe('Data Adapters - MemoryAdapter Implementation', () => {
  let memoryAdapter;

  beforeEach(async () => {
    memoryAdapter = new MemoryAdapter();
    await memoryAdapter.clear();
  });

  describe('findUserByEmail', () => {
    it('should correctly retrieve a user by email', async () => {
      // Create a user first
      const userData = {
        email: 'test@example.com',
        hashedPassword: 'hashed_password_123',
        role: 'user'
      };
      const createdUser = await memoryAdapter.createUser(userData);

      // Find the user
      const foundUser = await memoryAdapter.findUserByEmail('test@example.com');

      expect(foundUser).not.toBeNull();
      expect(foundUser.id).toBe(createdUser.id);
      expect(foundUser.email).toBe('test@example.com');
      expect(foundUser.hashedPassword).toBe('hashed_password_123');
    });

    it('should return null for non-existent user', async () => {
      const user = await memoryAdapter.findUserByEmail('nonexistent@example.com');
      expect(user).toBeNull();
    });

    it('should throw error if email is not a string', async () => {
      await expect(memoryAdapter.findUserByEmail(123))
        .rejects
        .toThrow('Email must be a string');
      
      await expect(memoryAdapter.findUserByEmail(null))
        .rejects
        .toThrow('Email must be a string');
      
      await expect(memoryAdapter.findUserByEmail({}))
        .rejects
        .toThrow('Email must be a string');
    });
  });

  describe('createUser', () => {
    it('should create a user with valid data', async () => {
      const userData = {
        email: 'newuser@example.com',
        hashedPassword: 'hashed_password_456',
        role: 'admin'
      };

      const createdUser = await memoryAdapter.createUser(userData);

      expect(createdUser).toHaveProperty('id');
      expect(createdUser.email).toBe('newuser@example.com');
      expect(createdUser.hashedPassword).toBe('hashed_password_456');
      expect(createdUser.role).toBe('admin');
      expect(createdUser).toHaveProperty('createdAt');
      expect(createdUser.createdAt instanceof Date).toBeTruthy();
    });

    it('should generate unique IDs for different users', async () => {
      const user1 = await memoryAdapter.createUser({
        email: 'user1@example.com',
        hashedPassword: 'hash1'
      });

      const user2 = await memoryAdapter.createUser({
        email: 'user2@example.com',
        hashedPassword: 'hash2'
      });

      expect(user1.id).not.toBe(user2.id);
    });

    it('should throw error for duplicate email', async () => {
      await memoryAdapter.createUser({
        email: 'duplicate@example.com',
        hashedPassword: 'hash1'
      });

      await expect(memoryAdapter.createUser({
        email: 'duplicate@example.com',
        hashedPassword: 'hash2'
      }))
        .rejects
        .toThrow('User with this email already exists');
    });

    it('should set default role if not provided', async () => {
      const user = await memoryAdapter.createUser({
        email: 'norole@example.com',
        hashedPassword: 'hash1'
      });

      expect(user.role).toBe('user');
    });

    it('should validate email format', async () => {
      await expect(memoryAdapter.createUser({
        email: 'invalid-email',
        hashedPassword: 'hash1'
      }))
        .rejects
        .toThrow();
    });

    it('should require hashedPassword to be a string', async () => {
      await expect(memoryAdapter.createUser({
        email: 'test@example.com',
        hashedPassword: 123
      }))
        .rejects
        .toThrow();
    });
  });

  describe('saveRefreshToken', () => {
    it('should persist token with correct expiry', async () => {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now

      await memoryAdapter.saveRefreshToken('user123', 'refresh_token_abc', expiresAt);

      const isValid = await memoryAdapter.isRefreshTokenValid('refresh_token_abc');
      expect(isValid).toBe(true);
    });

    it('should throw error if userId is not a string', async () => {
      await expect(memoryAdapter.saveRefreshToken(123, 'token', new Date()))
        .rejects
        .toThrow('Invalid parameters');
    });

    it('should throw error if token is not a string', async () => {
      await expect(memoryAdapter.saveRefreshToken('user123', 123, new Date()))
        .rejects
        .toThrow('Invalid parameters');
    });

    it('should throw error if expiresAt is not a Date', async () => {
      await expect(memoryAdapter.saveRefreshToken('user123', 'token', 'not-a-date'))
        .rejects
        .toThrow('Invalid parameters');
    });

    it('should throw error if token is too short', async () => {
      await expect(memoryAdapter.saveRefreshToken('user123', 'short', new Date()))
        .rejects
        .toThrow('Token too short');
    });

    it('should allow token to be reused after revocation', async () => {
      // First save
      await memoryAdapter.saveRefreshToken('user123', 'longtoken123', new Date(Date.now() + 86400000));
      
      // Revoke it
      await memoryAdapter.revokeRefreshToken('longtoken123');
      
      // Verify it's revoked
      expect(await memoryAdapter.isRefreshTokenValid('longtoken123')).toBe(false);
      
      // Save again (should work)
      await memoryAdapter.saveRefreshToken('user123', 'longtoken123', new Date(Date.now() + 86400000));
      
      // Verify it's valid again
      expect(await memoryAdapter.isRefreshTokenValid('longtoken123')).toBe(true);
    });
  });

  describe('isRefreshTokenValid', () => {
    it('should return true for valid token', async () => {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await memoryAdapter.saveRefreshToken('user123', 'valid_token', expiresAt);
      
      const isValid = await memoryAdapter.isRefreshTokenValid('valid_token');
      expect(isValid).toBe(true);
    });

    it('should return false for non-existent token', async () => {
      const isValid = await memoryAdapter.isRefreshTokenValid('nonexistent_token');
      expect(isValid).toBe(false);
    });

    it('should return false for revoked token', async () => {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await memoryAdapter.saveRefreshToken('user123', 'revoked_token', expiresAt);
      await memoryAdapter.revokeRefreshToken('revoked_token');
      
      const isValid = await memoryAdapter.isRefreshTokenValid('revoked_token');
      expect(isValid).toBe(false);
    });

    it('should return false for expired token', async () => {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() - 1); // Expired yesterday

      await memoryAdapter.saveRefreshToken('user123', 'expired_token', expiresAt);
      
      const isValid = await memoryAdapter.isRefreshTokenValid('expired_token');
      expect(isValid).toBe(false);
    });

    it('should throw error if token is not a string', async () => {
      await expect(memoryAdapter.isRefreshTokenValid(123))
        .rejects
        .toThrow('Token must be a string');
      
      await expect(memoryAdapter.isRefreshTokenValid(null))
        .rejects
        .toThrow('Token must be a string');
    });
  });

  describe('revokeRefreshToken', () => {
    it('should revoke a single token', async () => {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await memoryAdapter.saveRefreshToken('user123', 'token_to_revoke', expiresAt);
      
      // Verify it's valid before revocation
      expect(await memoryAdapter.isRefreshTokenValid('token_to_revoke')).toBe(true);
      
      // Revoke it
      await memoryAdapter.revokeRefreshToken('token_to_revoke');
      
      // Verify it's revoked
      expect(await memoryAdapter.isRefreshTokenValid('token_to_revoke')).toBe(false);
    });

    it('should throw error if token is not a string', async () => {
      await expect(memoryAdapter.revokeRefreshToken(123))
        .rejects
        .toThrow('Token must be a string');
      
      await expect(memoryAdapter.revokeRefreshToken(null))
        .rejects
        .toThrow('Token must be a string');
    });

    it('should not throw error when revoking non-existent token', async () => {
      // Should not throw even if token doesn't exist
      await expect(memoryAdapter.revokeRefreshToken('nonexistent_token'))
        .resolves
        .not.toThrow();
    });
  });

  describe('revokeAllUserSessions', () => {
    it('should invalidate every token for a specific userId', async () => {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      // Create tokens for user123
      await memoryAdapter.saveRefreshToken('user123', 'token1_user123', expiresAt);
      await memoryAdapter.saveRefreshToken('user123', 'token2_user123', expiresAt);
      await memoryAdapter.saveRefreshToken('user123', 'token3_user123', expiresAt);
      
      // Create tokens for user456 (should not be affected)
      await memoryAdapter.saveRefreshToken('user456', 'token1_user456', expiresAt);
      
      // Verify all tokens are valid before revocation
      expect(await memoryAdapter.isRefreshTokenValid('token1_user123')).toBe(true);
      expect(await memoryAdapter.isRefreshTokenValid('token2_user123')).toBe(true);
      expect(await memoryAdapter.isRefreshTokenValid('token3_user123')).toBe(true);
      expect(await memoryAdapter.isRefreshTokenValid('token1_user456')).toBe(true);
      
      // Revoke all sessions for user123
      await memoryAdapter.revokeAllUserSessions('user123');
      
      // Verify user123's tokens are revoked
      expect(await memoryAdapter.isRefreshTokenValid('token1_user123')).toBe(false);
      expect(await memoryAdapter.isRefreshTokenValid('token2_user123')).toBe(false);
      expect(await memoryAdapter.isRefreshTokenValid('token3_user123')).toBe(false);
      
      // Verify user456's token is still valid
      expect(await memoryAdapter.isRefreshTokenValid('token1_user456')).toBe(true);
    });

    it('should throw error if userId is not a string', async () => {
      await expect(memoryAdapter.revokeAllUserSessions(123))
        .rejects
        .toThrow('User ID must be a string');
      
      await expect(memoryAdapter.revokeAllUserSessions(null))
        .rejects
        .toThrow('User ID must be a string');
    });

    it('should not throw error when revoking sessions for non-existent user', async () => {
      // Should not throw even if user doesn't exist
      await expect(memoryAdapter.revokeAllUserSessions('nonexistent_user'))
        .resolves
        .not.toThrow();
    });
  });
});