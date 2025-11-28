/**
 * Nguard - JWT utilities for encryption and decryption
 */

import jwt from 'jsonwebtoken';
import { SessionPayload } from './types';
import crypto from 'crypto';

export class JWTHandler {
  private secret: string;
  private algorithm: jwt.Algorithm = 'HS256';

  constructor(secret: string) {
    if (!secret || secret.length < 32) {
      throw new Error('JWT secret must be at least 32 characters long');
    }
    this.secret = secret;
  }

  /**
   * Create a signed JWT token from payload
   */
  encode(payload: SessionPayload): string {
    try {
      // Don't use expiresIn since payload already has exp
      // jwt.sign will automatically set exp if expiresIn is provided
      // but payload already contains exp, so we just sign without expiresIn
      return jwt.sign(payload, this.secret, {
        algorithm: this.algorithm,
        // expiresIn should not be used when payload has exp already
        noTimestamp: false,
      });
    } catch (error) {
      // SECURITY: Only log detailed errors in development
      if (process.env.NODE_ENV === 'development') {
        console.error('Error encoding JWT:', error);
      }
      throw new Error('Failed to encode JWT token');
    }
  }

  /**
   * Verify and decode a JWT token
   * Security: Does not leak error details in production
   */
  decode(token: string): SessionPayload | null {
    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: [this.algorithm],
      });
      return decoded as SessionPayload;
    } catch (error) {
      // SECURITY: Only log detailed errors in development to prevent information leakage
      // Production logs should not reveal JWT internals or validation failures
      if (process.env.NODE_ENV === 'development') {
        console.error('Error decoding JWT:', error);
      }
      return null;
    }
  }

  /**
   * Generate a cryptographically secure session ID
   */
  static generateSessionId(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Hash a value using SHA-256
   */
  static hash(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex');
  }
}
