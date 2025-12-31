import argon2 from 'argon2';
import { SignJWT, jwtVerify } from 'jose';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Hashes a plain text password using Argon2
 * @param {string} plain - The plain text password to hash
 * @returns {Promise<string>} The hashed password
 */
export async function hashPassword(plain) {
  if (typeof plain !== 'string') {
    throw new Error('Password must be a string');
  }
  return await argon2.hash(plain);
}

/**
 * Verifies a plain text password against a hashed password using Argon2
 * @param {string} hash - The hashed password
 * @param {string} plain - The plain text password to verify
 * @returns {Promise<boolean>} True if the password matches, false otherwise
 */
export async function verifyPassword(hash, plain) {
  if (typeof hash !== 'string' || typeof plain !== 'string') {
    throw new Error('Hash and plain text must be strings');
  }
  // Always compare to prevent timing attacks
  return await argon2.verify(hash, plain);
}

/**
 * Signs an access token with 15-minute expiry
 * @param {object} payload - The payload to sign
 * @returns {Promise<string>} The signed JWT
 */
export async function signAccessToken(payload) {
  const secret = new TextEncoder().encode(process.env.ACCESS_TOKEN_SECRET);
  
  if (!secret || secret.length < 32) {
    throw new Error('ACCESS_TOKEN_SECRET must be at least 32 characters');
  }
  
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('15m')
    .setJti(crypto.randomUUID()) // Add unique JWT ID
    .sign(secret);
}

/**
 * Signs a refresh token with 7-day expiry
 * @param {object} payload - The payload to sign
 * @returns {Promise<string>} The signed JWT
 */
export async function signRefreshToken(payload) {
  const secret = new TextEncoder().encode(process.env.REFRESH_TOKEN_SECRET);
  
  if (!secret || secret.length < 32) {
    throw new Error('REFRESH_TOKEN_SECRET must be at least 32 characters');
  }
  
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .setJti(crypto.randomUUID()) // Add unique JWT ID
    .sign(secret);
}

/**
 * Verifies a JWT token
 * @param {string} token - The JWT token to verify
 * @param {string} type - The token type ('access' or 'refresh')
 * @returns {Promise<object>} The verified payload
 */
export async function verifyJWT(token, type) {
  if (typeof token !== 'string') {
    throw new Error('Token must be a string');
  }
  
  const secret = new TextEncoder().encode(
    type === 'access' 
      ? process.env.ACCESS_TOKEN_SECRET 
      : process.env.REFRESH_TOKEN_SECRET
  );
  
  if (!secret || secret.length < 32) {
    throw new Error(`${type.toUpperCase()}_TOKEN_SECRET must be at least 32 characters`);
  }
  
  try {
    const { payload } = await jwtVerify(token, secret, {
      algorithms: ['HS256']
    });
    return payload;
  } catch (error) {
    throw new Error('Invalid token');
  }
}