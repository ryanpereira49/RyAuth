# API Reference

Complete API documentation for RyAuth authentication library.

## AuthService

The main service class that orchestrates authentication flows.

### Constructor

```javascript
new AuthService(adapter)
```

**Parameters:**
- `adapter` (BaseAdapter): Database adapter instance

### Methods

#### `register(email, password)`

Register a new user account.

```javascript
const result = await authService.register('user@example.com', 'password123');
```

**Parameters:**
- `email` (string): User's email address
- `password` (string): User's password (minimum 8 characters)

**Returns:** `Promise<{success: boolean, userId: string}>`

**Throws:** Error for validation failures or duplicate users

#### `login(email, password)`

Authenticate a user and return tokens.

```javascript
const result = await authService.login('user@example.com', 'password123');
```

**Parameters:**
- `email` (string): User's email address
- `password` (string): User's password

**Returns:** `Promise<{success: boolean, accessToken: string, refreshToken: string, user: object}>`

**Throws:** Error for invalid credentials

#### `refresh(refreshToken)`

Refresh access and refresh tokens.

```javascript
const result = await authService.refresh('refresh_token_here');
```

**Parameters:**
- `refreshToken` (string): Valid refresh token

**Returns:** `Promise<{success: boolean, accessToken: string, refreshToken: string}>`

**Throws:** Error for invalid or expired tokens

#### `revokeRefreshToken(refreshToken)`

Revoke a refresh token (logout).

```javascript
await authService.revokeRefreshToken('refresh_token_here');
```

**Parameters:**
- `refreshToken` (string): Refresh token to revoke

**Returns:** `Promise<void>`

## Middleware

Express.js middleware for JWT authentication and authorization.

### `createAuthMiddleware(config)`

Create an authentication middleware instance.

```javascript
const authMiddleware = createAuthMiddleware({
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET
});
```

**Parameters:**
- `config` (object):
  - `accessTokenSecret` (string): Secret for access tokens (min 32 chars)
  - `refreshTokenSecret` (string): Secret for refresh tokens (min 32 chars)

**Returns:** AuthMiddleware instance with `authenticate` and `authorize` methods

### `authenticate`

Middleware to verify JWT access tokens.

```javascript
app.get('/protected', authMiddleware.authenticate, (req, res) => {
  res.json({ user: req.user });
});
```

Attaches `req.user` with user payload if token is valid.

### `authorize(...roles)`

Middleware for role-based access control.

```javascript
app.get('/admin', authMiddleware.authenticate, authMiddleware.authorize('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});
```

**Parameters:**
- `...roles` (string[]): Allowed roles

## Adapters

Database abstraction layer using the adapter pattern.

### BaseAdapter

Abstract base class for database adapters.

**Required Methods:**
- `findUserByEmail(email)`: Find user by email
- `createUser(userData)`: Create new user
- `saveRefreshToken(userId, token, expiresAt)`: Save refresh token
- `findRefreshToken(token)`: Find refresh token
- `revokeRefreshToken(token)`: Revoke refresh token
- `isRefreshTokenRevoked(token)`: Check if token is revoked

### MemoryAdapter

In-memory adapter for development and testing.

```javascript
import { MemoryAdapter } from 'ryauth';

const adapter = new MemoryAdapter();
```

## Crypto Utilities

Low-level cryptographic functions (advanced usage).

### `hashPassword(plain)`

Hash a password with Argon2.

```javascript
const hash = await hashPassword('password123');
```

### `verifyPassword(hash, plain)`

Verify a password against its hash.

```javascript
const isValid = await verifyPassword(hash, 'password123');
```

### `signAccessToken(payload)`

Sign an access token (15-minute expiry).

### `signRefreshToken(payload)`

Sign a refresh token (7-day expiry).

### `verifyJWT(token, secret)`

Verify and decode a JWT token.

## Error Handling

RyAuth throws descriptive errors for various failure conditions:

- **Validation Errors**: Invalid input data
- **Authentication Errors**: Invalid credentials, expired tokens
- **Authorization Errors**: Insufficient permissions
- **Adapter Errors**: Database operation failures

Always wrap operations in try-catch blocks:

```javascript
try {
  const result = await authService.login(email, password);
  res.json(result);
} catch (error) {
  res.status(400).json({ error: error.message });
}
```