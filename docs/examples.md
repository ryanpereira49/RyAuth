# Examples

Practical examples for integrating RyAuth into your applications.

## Basic Express.js Setup

```javascript
import express from 'express';
import { createAuthMiddleware, AuthService, MemoryAdapter } from 'ryauth';

const app = express();
app.use(express.json());

// Initialize
const adapter = new MemoryAdapter();
const authService = new AuthService(adapter);
const authMiddleware = createAuthMiddleware({
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET
});

// Routes
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await authService.register(email, password);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await authService.login(email, password);
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

app.get('/api/profile', authMiddleware.authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

## Role-Based Access Control

```javascript
// Admin-only route
app.get('/api/admin/users',
  authMiddleware.authenticate,
  authMiddleware.authorize('admin'),
  (req, res) => {
    res.json({ users: [] }); // Return user list
  }
);

// Multiple roles allowed
app.get('/api/content',
  authMiddleware.authenticate,
  authMiddleware.authorize('user', 'editor', 'admin'),
  (req, res) => {
    res.json({ content: 'Protected content' });
  }
);
```

## Token Refresh

```javascript
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const result = await authService.refresh(refreshToken);
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});
```

## Logout (Token Revocation)

```javascript
app.post('/auth/logout', authMiddleware.authenticate, async (req, res) => {
  try {
    // Get refresh token from request (could be in body, cookie, etc.)
    const { refreshToken } = req.body;
    await authService.revokeRefreshToken(refreshToken);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

## Custom Database Adapter

```javascript
import { BaseAdapter } from 'ryauth';

export class PostgreSQLAdapter extends BaseAdapter {
  constructor(db) {
    super();
    this.db = db; // Your database connection
  }

  async findUserByEmail(email) {
    const result = await this.db.query(
      'SELECT id, email, hashed_password, role FROM users WHERE email = $1',
      [email]
    );
    return result.rows[0] || null;
  }

  async createUser(userData) {
    const result = await this.db.query(
      'INSERT INTO users (email, hashed_password, role) VALUES ($1, $2, $3) RETURNING *',
      [userData.email, userData.hashedPassword, userData.role]
    );
    return result.rows[0];
  }

  async saveRefreshToken(userId, token, expiresAt) {
    await this.db.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [userId, token, expiresAt]
    );
  }

  async findRefreshToken(token) {
    const result = await this.db.query(
      'SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()',
      [token]
    );
    return result.rows[0] || null;
  }

  async revokeRefreshToken(token) {
    await this.db.query(
      'DELETE FROM refresh_tokens WHERE token = $1',
      [token]
    );
  }

  async isRefreshTokenRevoked(token) {
    const result = await this.db.query(
      'SELECT 1 FROM refresh_tokens WHERE token = $1',
      [token]
    );
    return result.rows.length === 0;
  }
}
```

## Testing with RyAuth

```javascript
import { AuthService, MemoryAdapter } from 'ryauth';

describe('Authentication', () => {
  let authService;
  let adapter;

  beforeEach(() => {
    adapter = new MemoryAdapter();
    authService = new AuthService(adapter);
  });

  it('should register a new user', async () => {
    const result = await authService.register('test@example.com', 'password123');
    expect(result.success).toBe(true);
    expect(result.userId).toBeDefined();
  });

  it('should login with correct credentials', async () => {
    await authService.register('test@example.com', 'password123');
    const result = await authService.login('test@example.com', 'password123');

    expect(result.success).toBe(true);
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
  });
});
```

## Environment Configuration

```javascript
// .env
ACCESS_TOKEN_SECRET=your_super_secret_access_token_key_here_minimum_32_chars
REFRESH_TOKEN_SECRET=your_super_secret_refresh_token_key_here_minimum_32_chars

// Generate secure secrets
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Error Handling

```javascript
// Always wrap auth operations in try-catch
app.post('/auth/register', async (req, res) => {
  try {
    const result = await authService.register(req.body.email, req.body.password);
    res.json(result);
  } catch (error) {
    // Handle validation errors, duplicate users, etc.
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const result = await authService.login(req.body.email, req.body.password);
    res.json(result);
  } catch (error) {
    // Handle invalid credentials
    res.status(401).json({ error: error.message });
  }
});
```