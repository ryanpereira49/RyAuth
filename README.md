# RyAuth

[![npm version](https://badge.fury.io/js/ryauth.svg)](https://badge.fury.io/js/ryauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![Test Coverage](https://img.shields.io/badge/coverage-94%25-green)](https://github.com/ryanpereira49/RyAuth)
[![GitHub Issues](https://img.shields.io/github/issues/ryanpereira49/RyAuth)](https://github.com/ryanpereira49/RyAuth/issues)

A modern, secure, and database-agnostic authentication library for Node.js. Built with JWT tokens, Argon2 password hashing, and role-based access control (RBAC).

## ✨ Features

- 🔐 **Secure Authentication** - JWT-based authentication with access and refresh tokens
- 🛡️ **Password Security** - Argon2 password hashing (winner of the 2015 Password Hashing Competition)
- 🔄 **Token Rotation** - Automatic refresh token rotation for enhanced security
- 👥 **Role-Based Access Control** - Fine-grained permissions and user roles
- 🗄️ **Database Agnostic** - Adapter pattern supports any database (PostgreSQL, MongoDB, MySQL, etc.)
- 🚀 **Modern JavaScript** - ES modules, async/await, and TypeScript-ready
- ✅ **Runtime Validation** - Zod schemas for input validation and type safety
- 🧪 **Comprehensive Testing** - 66 tests with 94% code coverage
- 📚 **Full Documentation** - Complete API reference and examples

## 📦 Installation

```bash
npm install ryauth
# or
yarn add ryauth
# or
pnpm add ryauth
```

## 🚀 Quick Start

```javascript
import express from 'express';
import { createAuthMiddleware, AuthService, MemoryAdapter } from 'ryauth';

const app = express();
app.use(express.json());

// Initialize authentication
const adapter = new MemoryAdapter();
const authService = new AuthService(adapter);

// Create middleware
const authMiddleware = createAuthMiddleware({
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET
});

// Register endpoint
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await authService.register(email, password);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login endpoint
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await authService.login(email, password);
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Protected route
app.get('/api/profile', authMiddleware.authenticate, (req, res) => {
  res.json({ user: req.user });
});

// Admin-only route
app.get('/api/admin', authMiddleware.authenticate, authMiddleware.authorize('admin'), (req, res) => {
  res.json({ message: 'Welcome, admin!' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## 🔧 Environment Setup

Create a `.env` file in your project root:

```env
# Access Token Secret (minimum 32 characters)
ACCESS_TOKEN_SECRET=your_32+_character_access_token_secret_here

# Refresh Token Secret (minimum 32 characters)
REFRESH_TOKEN_SECRET=your_32+_character_refresh_token_secret_here
```

## 🏗️ Architecture

RyAuth uses a modular architecture designed for security and flexibility:

```
src/
├── core/
│   └── crypto.js          # Argon2 & JOSE JWT operations
├── adapters/
│   ├── base.js           # Abstract database adapter interface
│   └── memory.js         # In-memory adapter for testing
├── middleware/
│   └── auth.js           # Express middleware for JWT validation
└── services/
    └── auth-service.js   # Core authentication business logic
```

## 📚 API Overview

### AuthService

The main service class that orchestrates authentication flows.

```javascript
const authService = new AuthService(adapter);

// User management
await authService.register('user@example.com', 'password123');
await authService.login('user@example.com', 'password123');
await authService.refresh(refreshToken);
await authService.revokeRefreshToken(refreshToken);
```

### Middleware

Express.js middleware for authentication and authorization.

```javascript
const authMiddleware = createAuthMiddleware(config);

// Authentication
app.get('/protected', authMiddleware.authenticate, handler);

// Authorization
app.get('/admin', authMiddleware.authenticate, authMiddleware.authorize('admin'), handler);
```

### Adapters

Database abstraction layer supporting multiple databases.

```javascript
// Built-in MemoryAdapter for testing
const adapter = new MemoryAdapter();

// Custom adapter for PostgreSQL
class PostgreSQLAdapter extends BaseAdapter {
  async findUserByEmail(email) { /* implementation */ }
  async createUser(userData) { /* implementation */ }
  // ... other required methods
}
```

## 🧪 Testing

```bash
npm test
```

RyAuth includes comprehensive test coverage:
- **66 tests** covering all functionality
- **94% code coverage**
- Unit tests for all core modules
- Integration tests for complete flows

## 📖 Documentation

- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Examples](docs/examples.md)** - Practical code examples and integrations
- **[Contributing Guide](CONTRIBUTING.md)** - Guidelines for contributors

## 🔒 Security Features

- **Argon2 Password Hashing** - Memory-hard algorithm resistant to brute force attacks
- **JWT Token Rotation** - Automatic refresh token rotation prevents token theft
- **Session Management** - Ability to revoke refresh tokens
- **Input Validation** - Runtime validation with Zod schemas
- **Timing-Safe Comparison** - Prevents timing attacks during authentication
- **Secure Defaults** - 15-minute access tokens, 7-day refresh tokens

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/ryanpereira49/RyAuth.git
cd RyAuth

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Run tests
npm test
```

## 📄 License

MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [JOSE](https://github.com/panva/jose) for JWT operations
- Password hashing powered by [Argon2](https://github.com/ranisalt/node-argon2)
- Runtime validation with [Zod](https://github.com/colinhacks/zod)

## 📞 Support

- 🐛 [Issues](https://github.com/ryanpereira49/RyAuth/issues)
- 💬 [Discussions](https://github.com/ryanpereira49/RyAuth/discussions)
- 📧 Contact: ryanpereira499@gmail.com

---

**Made with ❤️ for secure Node.js applications**

*RyAuth - Modern Authentication, Simplified.*