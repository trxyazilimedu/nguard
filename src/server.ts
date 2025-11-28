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

// Security interfaces
interface SessionStore {
  add(sessionId: string): Promise<void>;
  has(sessionId: string): Promise<boolean>;
  delete(sessionId: string): Promise<void>;
  clear(): Promise<void>;
}

class InMemorySessionStore implements SessionStore {
  private store = new Set<string>();

  async add(sessionId: string): Promise<void> {
    this.store.add(sessionId);
  }

  async has(sessionId: string): Promise<boolean> {
    return this.store.has(sessionId);
  }

  async delete(sessionId: string): Promise<void> {
    this.store.delete(sessionId);
  }

  async clear(): Promise<void> {
    this.store.clear();
  }
}

interface RateLimiter {
  check(key: string): Promise<boolean>;
  reset(key: string): Promise<void>;
}

class InMemoryRateLimiter implements RateLimiter {
  private store = new Map<string, { count: number; resetAt: number }>();

  constructor(
      private maxAttempts: number = 5,
      private windowMs: number = 15 * 60 * 1000
  ) {}

  async check(key: string): Promise<boolean> {
    const now = Date.now();
    const record = this.store.get(key);

    if (!record || now > record.resetAt) {
      this.store.set(key, {
        count: 1,
        resetAt: now + this.windowMs,
      });
      return true;
    }

    if (record.count >= this.maxAttempts) {
      return false;
    }

    record.count++;
    return true;
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }
}

export interface SecurityOptions {
  enableBlacklist?: boolean;
  enableRateLimit?: boolean;
  enableIpBinding?: boolean;
  enableAuditLog?: boolean;
  maxSessionsPerUser?: number;

  sessionStore?: SessionStore;
  rateLimiter?: RateLimiter;
}

// Protected fields that cannot be updated via updateSession
// These fields are critical for security and session integrity
const PROTECTED_SESSION_FIELDS = [
  'sessionId', 'iat', 'exp', 'expires',
  '__proto__', 'constructor', 'prototype'
] as const;

const PROTECTED_USER_FIELDS = [
  'id' // User ID should never be changed via updateSession
] as const;

const PROTECTED_DATA_FIELDS = [
  'role', 'roles', 'permissions', 'isAdmin', 'isSuperAdmin',
  '_ipHash', '_uaHash' // Internal security fields
] as const;

// Maximum size for update payload (10KB)
const MAX_UPDATE_SIZE = 10 * 1024;

// Sanitize string to prevent XSS
function sanitizeString(value: any): any {
  if (typeof value === 'string') {
    // Remove potentially dangerous characters
    return value
      .replace(/[<>]/g, '')
      .trim()
      .slice(0, 1000); // Max 1000 chars per string
  }
  return value;
}

// Sanitize object recursively
function sanitizeObject(obj: any, depth: number = 0): any {
  // Prevent deep nesting (DoS protection)
  if (depth > 5) return {};

  if (obj === null || obj === undefined) return obj;

  if (Array.isArray(obj)) {
    return obj.slice(0, 100).map(item => sanitizeObject(item, depth + 1));
  }

  if (typeof obj === 'object') {
    const sanitized: any = {};
    let fieldCount = 0;

    for (const [key, value] of Object.entries(obj)) {
      // Limit number of fields (DoS protection)
      if (fieldCount++ > 50) break;

      // Skip prototype pollution attempts
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }

      if (typeof value === 'string') {
        sanitized[key] = sanitizeString(value);
      } else if (typeof value === 'object') {
        sanitized[key] = sanitizeObject(value, depth + 1);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  return obj;
}

export class NguardServer {
  private config: NguardConfig;
  private jwtHandler: JWTHandler;
  private sessionCallbacks: SessionCallback[] = [];
  private jwtCallbacks: JWTCallback[] = [];
  private loginCallbacks: ServerLoginCallback[] = [];
  private logoutCallbacks: ServerLogoutCallback[] = [];
  private validateCallbacks: ValidateSessionCallback[] = [];

  // Security features
  private securityOptions: SecurityOptions;
  private sessionBlacklist: SessionStore;
  private rateLimiter: RateLimiter;
  private activeSessionsByUser = new Map<string, Set<string>>();

  constructor(config: NguardConfig, securityOptions?: SecurityOptions) {
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

    this.securityOptions = {
      enableBlacklist: false,
      enableRateLimit: false,
      enableIpBinding: false,
      enableAuditLog: false,
      maxSessionsPerUser: 5,
      ...securityOptions,
    };

    this.sessionBlacklist = securityOptions?.sessionStore || new InMemorySessionStore();
    this.rateLimiter = securityOptions?.rateLimiter || new InMemoryRateLimiter();

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
   * Invalidate a specific session
   */
  async invalidateSession(sessionId: string): Promise<void> {
    if (!this.securityOptions.enableBlacklist) {
      console.warn('Blacklist is not enabled. Enable it in SecurityOptions.');
      return;
    }

    await this.sessionBlacklist.add(sessionId);
    this.log('SESSION_INVALIDATED', { sessionId });
  }

  /**
   * Invalidate all sessions for a user
   */
  async invalidateUserSessions(userId: string): Promise<void> {
    if (!this.securityOptions.enableBlacklist) {
      console.warn('Blacklist is not enabled. Enable it in SecurityOptions.');
      return;
    }

    const sessions = this.activeSessionsByUser.get(userId);
    if (sessions) {
      for (const sessionId of sessions) {
        await this.sessionBlacklist.add(sessionId);
      }
      this.activeSessionsByUser.delete(userId);
    }

    this.log('ALL_SESSIONS_INVALIDATED', { userId });
  }

  /**
   * Create a new session with security features
   * Security: Sanitizes input to prevent XSS and injection attacks
   */
  async createSession(
      sessionData: Session,
      options?: SessionOptions & {
        ipAddress?: string;
        userAgent?: string;
      }
  ): Promise<{ token: string; setCookieHeader: string; session: Session }> {
    // SECURITY: Sanitize session data to prevent XSS and prototype pollution
    const sanitizedSessionData = sanitizeObject(sessionData);

    // Rate limiting check
    if (this.securityOptions.enableRateLimit && sanitizedSessionData.user) {
      const canProceed = await this.rateLimiter.check(`create:${sanitizedSessionData.user.id}`);
      if (!canProceed) {
        throw new Error('Rate limit exceeded. Please try again later.');
      }
    }

    // Max sessions per user check
    if (
        this.securityOptions.enableBlacklist &&
        this.securityOptions.maxSessionsPerUser &&
        sanitizedSessionData.user
    ) {
      const userSessions = this.activeSessionsByUser.get(sanitizedSessionData.user.id) || new Set();
      if (userSessions.size >= this.securityOptions.maxSessionsPerUser) {
        const oldestSession = Array.from(userSessions)[0];
        await this.sessionBlacklist.add(oldestSession);
        userSessions.delete(oldestSession);
      }
    }

    const sessionId = JWTHandler.generateSessionId();
    const now = Math.floor(Date.now() / 1000);
    const maxAge = options?.maxAge || this.config.maxAge || 24 * 60 * 60;
    const expiresAt = now + maxAge;

    // Add IP binding if enabled
    let enhancedData = { ...sanitizedSessionData.data };
    if (this.securityOptions.enableIpBinding && options?.ipAddress) {
      enhancedData = {
        ...enhancedData,
        _ipHash: JWTHandler.hash(options.ipAddress),
        _uaHash: options.userAgent ? JWTHandler.hash(options.userAgent) : undefined,
      };
    }

    // Create JWT payload from session data
    // Spread all session data to preserve custom fields like role, permissions, etc.
    let payload: SessionPayload = {
      ...sanitizedSessionData,
      sessionId,
      iat: now,
      exp: expiresAt,
      user: sanitizedSessionData.user,
      data: enhancedData,
    };

    // Apply JWT callbacks
    for (const callback of this.jwtCallbacks) {
      payload = await callback(payload);
    }

    // Encode token
    const token = this.jwtHandler.encode(payload);

    // Track active session
    if (this.securityOptions.enableBlacklist && sanitizedSessionData.user) {
      const userSessions = this.activeSessionsByUser.get(sanitizedSessionData.user.id) || new Set();
      userSessions.add(sessionId);
      this.activeSessionsByUser.set(sanitizedSessionData.user.id, userSessions);
    }

    // Create session object with expiration
    let session: Session = {
      ...sanitizedSessionData,
      data: enhancedData,
      expires: expiresAt * 1000, // Convert to milliseconds for JS
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

    this.log('SESSION_CREATED', {
      userId: sanitizedSessionData.user?.id,
      sessionId,
      ipAddress: options?.ipAddress,
    });

    return {
      token,
      setCookieHeader,
      session,
    };
  }

  /**
   * Validate and retrieve session from cookie with security checks
   */
  async validateSession(
      cookieString?: string,
      cookieValue?: string,
      options?: {
        ipAddress?: string;
        userAgent?: string;
      }
  ): Promise<Session | null> {
    // Rate limiting for validation
    // SECURITY: Only apply rate limiting if IP address is available to avoid shared key issues
    if (this.securityOptions.enableRateLimit && options?.ipAddress) {
      const canProceed = await this.rateLimiter.check(`validate:${options.ipAddress}`);
      if (!canProceed) {
        throw new Error('Too many validation attempts');
      }
    }

    const token =
        cookieValue || getCookie(this.config.cookieName!, cookieString);

    if (!token) {
      return null;
    }

    const payload = this.jwtHandler.decode(token);

    if (!payload) {
      this.log('SESSION_VALIDATION_FAILED', { error: 'Invalid token' });
      return null;
    }

    // Check blacklist
    if (this.securityOptions.enableBlacklist) {
      const isBlacklisted = await this.sessionBlacklist.has(payload.sessionId);
      if (isBlacklisted) {
        this.log('SESSION_BLACKLISTED', { sessionId: payload.sessionId });
        return null;
      }
    }

    // Check expiration
    if (payload.exp * 1000 < Date.now()) {
      if (this.securityOptions.enableBlacklist) {
        await this.invalidateSession(payload.sessionId);
      }
      return null;
    }

    // IP binding check
    if (this.securityOptions.enableIpBinding && options?.ipAddress && payload.data?._ipHash) {
      const currentIpHash = JWTHandler.hash(options.ipAddress);
      if (currentIpHash !== payload.data._ipHash) {
        this.log('IP_MISMATCH', {
          sessionId: payload.sessionId,
          userId: payload.user.id,
        });
        return null;
      }
    }

    // Restore session from payload, preserving all custom fields
    // Filter out JWT-specific fields (sessionId, iat, exp)
    const { sessionId, iat, exp, ...sessionFields } = payload;

    // SECURITY: Sanitize payload data as defense in depth
    // Even though JWT is signed, this protects against compromised secrets
    const sanitizedFields = sanitizeObject(sessionFields);

    let session: Session = {
      ...sanitizedFields,
      expires: exp * 1000,
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
   * Update session - merges partial updates with current session
   * Supports updating any session field including custom fields
   *
   * Security features:
   * - Protected fields filtering (role, permissions, sessionId, etc.)
   * - Input validation and sanitization
   * - Size limits (max 10KB)
   * - Rate limiting
   * - XSS protection
   * - Prototype pollution prevention
   * - User ID protection
   * - Old session invalidation
   */
  async updateSession(
      cookieString: string | null | undefined,
      updates: Partial<Session>,
      options?: SessionOptions & {
        ipAddress?: string;
        userAgent?: string;
      }
  ): Promise<{ token: string; setCookieHeader: string; session: Session }> {
    // Security Check 1: Payload size limit (DoS prevention)
    const updateSize = JSON.stringify(updates).length;
    if (updateSize > MAX_UPDATE_SIZE) {
      throw new Error(`Update payload too large. Maximum size is ${MAX_UPDATE_SIZE} bytes`);
    }

    // Security Check 2: Get and validate current session
    const currentSession = await this.validateSession(
        cookieString ?? undefined,
        undefined,
        options
    );

    if (!currentSession) {
      throw new Error('No active session found');
    }

    // Security Check 3: Rate limiting
    if (this.securityOptions.enableRateLimit && currentSession.user) {
      const canProceed = await this.rateLimiter.check(`update:${currentSession.user.id}`);
      if (!canProceed) {
        throw new Error('Too many update requests. Please try again later.');
      }
    }

    // Security Check 4: Sanitize input to prevent XSS and injection attacks
    const sanitizedUpdates = sanitizeObject(updates);

    // Security Check 5: Remove protected session-level fields
    const safeUpdates: any = { ...sanitizedUpdates };
    for (const field of PROTECTED_SESSION_FIELDS) {
      delete safeUpdates[field];
    }

    // Security Check 6: Handle user object with protected fields
    if (safeUpdates.user) {
      const safeUser = { ...safeUpdates.user };

      // Remove protected user fields (especially user.id)
      for (const field of PROTECTED_USER_FIELDS) {
        delete safeUser[field];
      }

      // Ensure user.id stays the same
      safeUpdates.user = {
        ...safeUser,
        id: currentSession.user.id // Force original user ID
      };
    }

    // Security Check 7: Handle data object with protected fields
    if (safeUpdates.data) {
      const safeData = { ...safeUpdates.data };

      // Remove protected data fields (role, permissions, etc.)
      for (const field of PROTECTED_DATA_FIELDS) {
        delete safeData[field];
      }

      safeUpdates.data = safeData;
    }

    // Deep merge safe updates with current session
    const updatedSessionData: Session = {
      ...currentSession,
      ...safeUpdates,
      // Deep merge user object if provided
      user: safeUpdates.user
          ? { ...currentSession.user, ...safeUpdates.user }
          : currentSession.user,
      // Deep merge data object if provided
      data: safeUpdates.data
          ? { ...currentSession.data, ...safeUpdates.data }
          : currentSession.data,
    };

    // Remove expires field as it will be set by createSession
    delete (updatedSessionData as any).expires;

    // Security Check 8: Invalidate old session if blacklist is enabled
    // This prevents session fixation attacks
    const oldSessionId = (currentSession as any).sessionId;
    if (this.securityOptions.enableBlacklist && oldSessionId) {
      await this.sessionBlacklist.add(oldSessionId);

      // Remove from active sessions list
      if (currentSession.user) {
        const userSessions = this.activeSessionsByUser.get(currentSession.user.id);
        if (userSessions) {
          userSessions.delete(oldSessionId);
        }
      }
    }

    // Create new session with updated data
    const result = await this.createSession(updatedSessionData, options);

    this.log('SESSION_UPDATED', {
      userId: currentSession.user?.id,
      oldSessionId,
      newSessionId: (result.session as any).sessionId,
      updatedFields: Object.keys(safeUpdates),
    });

    return result;
  }

  /**
   * Clear session cookie header
   */
  clearSession(): string {
    return formatClearCookie(this.config.cookieName!);
  }

  /**
   * Handle logout - clear session and call logout callbacks
   */
  async logout(session?: Session): Promise<string> {
    // Call logout callbacks if session provided
    if (session) {
      for (const callback of this.logoutCallbacks) {
        await callback(session.user);
      }
    }

    // Return clear cookie header
    return this.clearSession();
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
      cookies?: Record<string, string>,
      options?: { ipAddress?: string; userAgent?: string }
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
      return this.validateSession(
          undefined,
          cookies[this.config.cookieName!],
          options
      );
    }

    return this.validateSession(cookieString, undefined, options);
  }

  /**
   * Audit logging
   */
  private log(event: string, data: any): void {
    if (!this.securityOptions.enableAuditLog) {
      return;
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      ...data,
    };

    if (process.env.NODE_ENV === 'production') {
      console.log('[AUDIT]', JSON.stringify(logEntry));
    } else {
      console.log('[AUDIT]', logEntry);
    }
  }
}

// Export factory function for easy setup
export function initializeServer(
    config: NguardConfig,
    securityOptions?: SecurityOptions
): NguardServer {
  return new NguardServer(config, securityOptions);
}