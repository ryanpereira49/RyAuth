// RyAuth - Authentication Middleware
// Provides JWT validation and role-based access control

import { jwtVerify, importJWK, importSPKI } from 'jose';
import { z } from 'zod';

// Configuration schema
const configSchema = z.object({
  accessTokenSecret: z.string().min(32),
  refreshTokenSecret: z.string().min(32),
});

// Error response schema
const errorSchema = z.object({
  error: z.string(),
});

// User payload schema
const userPayloadSchema = z.object({
  userId: z.string(),
  email: z.string().email(),
  role: z.string(),
  iat: z.number(),
  exp: z.number(),
});

class AuthMiddleware {
  #config;
  #accessKey;
  #refreshKey;

  constructor(config) {
    this.#config = configSchema.parse(config);
  }

  async #initializeKeys() {
    if (!this.#accessKey || !this.#refreshKey) {
      // Convert secrets to JWK format for jose
      this.#accessKey = await importJWK({ k: this.#config.accessTokenSecret, kty: 'oct' });
      this.#refreshKey = await importJWK({ k: this.#config.refreshTokenSecret, kty: 'oct' });
    }
  }

  // Extract token from Authorization header
  #extractToken(req) {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }

  // Verify JWT token
  async #verifyToken(token, key) {
    try {
      const result = await jwtVerify(token, key);
      return userPayloadSchema.parse(result.payload);
    } catch (error) {
      return null;
    }
  }

  // Authentication middleware - validates JWT
  async authenticate(req, res, next) {
    await this.#initializeKeys();

    const token = this.#extractToken(req);

    if (!token) {
      res.status(401).json(errorSchema.parse({ error: 'Unauthorized' }));
      return;
    }

    // Verify token using access key
    const payload = await this.#verifyToken(token, this.#accessKey);

    if (!payload) {
      res.status(403).json(errorSchema.parse({ error: 'Forbidden' }));
      return;
    }

    // Check if token is expired
    if (payload.exp * 1000 < Date.now()) {
      res.status(401).json(errorSchema.parse({ error: 'Unauthorized' }));
      return;
    }

    // Attach user to request
    req.user = payload;
    next();
  }

  // Authorization middleware - enforces role-based access control
  authorize(...allowedRoles) {
    return (req, res, next) => {
      // Check if user is authenticated
      if (!req.user) {
        res.status(401).json(errorSchema.parse({ error: 'Unauthorized' }));
        return;
      }

      // Check if user has required role
      if (!allowedRoles.includes(req.user.role)) {
        res.status(403).json(errorSchema.parse({ error: 'Forbidden' }));
        return;
      }

      next();
    };
  }
}

// Export middleware factory
export function createAuthMiddleware(config) {
  return new AuthMiddleware(config);
}

// Export middleware instances for convenience
export function authenticate(req, res, next) {
  throw new Error('AuthMiddleware must be initialized with config before use');
}

export function authorize(...roles) {
  throw new Error('AuthMiddleware must be initialized with config before use');
}
