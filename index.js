// RyAuth - Modern Authentication Library for Node.js
// Main entry point exporting all public APIs

// Core services
export { AuthService } from './src/services/auth-service.js';

// Middleware
export { createAuthMiddleware } from './src/middleware/auth.js';

// Adapters
export { BaseAdapter } from './src/adapters/base.js';
export { MemoryAdapter } from './src/adapters/memory.js';

// Core utilities (for advanced users)
export { hashPassword, verifyPassword, signAccessToken, signRefreshToken, verifyJWT } from './src/core/crypto.js';