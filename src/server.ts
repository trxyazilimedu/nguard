/**
 * Nguard - Server-side session management API
 */

import { JWTHandler } from './jwt';
import { formatSetCookie, formatClearCookie, getCookie, parseCookies } from './cookies';
import {
  Session,
  SessionUser,
  SessionData,
  NguardConfig,
  SessionOptions,
  SessionPayload,
  SessionCallback,
  JWTCallback,
} from './types';

/**
 * Server-side login callback
 * Used to authenticate user and create session
 */
export type ServerLoginCallback<T = any> = (
  credentials: T
) => Promise<{ user: SessionUser; data?: SessionData }>;

/**
 * Server-side logout callback
 * Used to clean up session on server
 */
export type ServerLogoutCallback = (user: SessionUser) => Promise<void>;

/**
 * Session validation callback
 * Used to validate session before allowing access
 */
export type ValidateSessionCallback = (session: Session) => Promise<boolean>;

export class NguardServer {
  private config: NguardConfig;
  private jwtHandler: JWTHandler;
  private sessionCallbacks: SessionCallback[] = [];
  private jwtCallbacks: JWTCallback[] = [];
  private loginCallbacks: ServerLoginCallback[] = [];
  private logoutCallbacks: ServerLogoutCallback[] = [];
  private validateCallbacks: ValidateSessionCallback[] = [];

  constructor(config: NguardConfig) {
    if (!config.secret || config.secret.length < 32) {
      throw new Error('Secret must be at least 32 characters long');
    }

    this.config = {
      cookieName: 'nguard-session',
      secure: true,
      sameSite: 'Lax',
      maxAge: 24 * 60 * 60, // 24 hours
      ...config,
    };

    this.jwtHandler = new JWTHandler(this.config.secret);
  }

  /**
   * Register a callback to transform session data
   */
  onSession(callback: SessionCallback): void {
    this.sessionCallbacks.push(callback);
  }

  /**
   * Register a callback to transform JWT payload
   */
  onJWT(callback: JWTCallback): void {
    this.jwtCallbacks.push(callback);
  }

  /**
   * Register a server-side login callback
   * Called during authentication process
   */
  onServerLogin(callback: ServerLoginCallback): void {
    this.loginCallbacks.push(callback);
  }

  /**
   * Register a server-side logout callback
   * Called during logout process
   */
  onServerLogout(callback: ServerLogoutCallback): void {
    this.logoutCallbacks.push(callback);
  }

  /**
   * Register a session validation callback
   * Called before allowing session usage
   */
  onValidateSession(callback: ValidateSessionCallback): void {
    this.validateCallbacks.push(callback);
  }

  /**
   * Create a new session
   */
  async createSession(
    user: SessionUser,
    data?: SessionData,
    options?: SessionOptions
  ): Promise<{ token: string; setCookieHeader: string; session: Session }> {
    const sessionId = JWTHandler.generateSessionId();
    const now = Math.floor(Date.now() / 1000);
    const maxAge = options?.maxAge || this.config.maxAge || 24 * 60 * 60;
    const expiresAt = now + maxAge;

    // Create JWT payload
    let payload: SessionPayload = {
      sessionId,
      user,
      iat: now,
      exp: expiresAt,
      data,
    };

    // Apply JWT callbacks
    for (const callback of this.jwtCallbacks) {
      payload = await callback(payload);
    }

    // Encode token
    const token = this.jwtHandler.encode(payload);

    // Create session object
    let session: Session = {
      user,
      expires: expiresAt * 1000, // Convert to milliseconds for JS
      data,
    };

    // Apply session callbacks
    for (const callback of this.sessionCallbacks) {
      session = await callback(session);
    }

    // Format Set-Cookie header
    const setCookieHeader = formatSetCookie(
      this.config.cookieName!,
      token,
      {
        maxAge,
        secure: this.config.secure,
        sameSite: this.config.sameSite,
      }
    );

    return {
      token,
      setCookieHeader,
      session,
    };
  }

  /**
   * Validate and retrieve session from cookie
   */
  async validateSession(
    cookieString?: string,
    cookieValue?: string
  ): Promise<Session | null> {
    const token =
      cookieValue || getCookie(this.config.cookieName!, cookieString);

    if (!token) {
      return null;
    }

    const payload = this.jwtHandler.decode(token);

    if (!payload) {
      return null;
    }

    // Check expiration
    if (payload.exp * 1000 < Date.now()) {
      return null;
    }

    let session: Session = {
      user: payload.user,
      expires: payload.exp * 1000,
      data: payload.data,
    };

    // Apply session callbacks
    for (const callback of this.sessionCallbacks) {
      session = await callback(session);
    }

    // Apply validation callbacks
    for (const callback of this.validateCallbacks) {
      const isValid = await callback(session);
      if (!isValid) {
        return null;
      }
    }

    return session;
  }

  /**
   * Update session data
   */
  async updateSession(
    user: SessionUser,
    data?: SessionData,
    options?: SessionOptions
  ): Promise<{ token: string; setCookieHeader: string; session: Session }> {
    return this.createSession(user, data, options);
  }

  /**
   * Clear session cookie header
   */
  clearSession(): string {
    return formatClearCookie(this.config.cookieName!);
  }

  /**
   * Get cookie name
   */
  getCookieName(): string {
    return this.config.cookieName!;
  }

  /**
   * Get session from request headers and body
   */
  async getSessionFromRequest(
    headers?: Record<string, string | string[] | undefined>,
    cookies?: Record<string, string>
  ): Promise<Session | null> {
    let cookieString = '';

    // Try to get cookie from headers
    if (headers) {
      const cookieHeader = headers['cookie'] || headers['Cookie'];
      if (typeof cookieHeader === 'string') {
        cookieString = cookieHeader;
      } else if (Array.isArray(cookieHeader)) {
        cookieString = cookieHeader[0];
      }
    }

    // Try to get cookie from cookies object
    if (cookies && cookies[this.config.cookieName!]) {
      return this.validateSession(undefined, cookies[this.config.cookieName!]);
    }

    return this.validateSession(cookieString);
  }
}

// Export factory function for easy setup
export function initializeServer(config: NguardConfig): NguardServer {
  return new NguardServer(config);
}
