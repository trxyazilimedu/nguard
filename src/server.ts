import { JWTHandler } from './jwt';
import { formatSetCookie, formatClearCookie, getCookie } from './cookies';
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

export class NguardServer {
  private config: NguardConfig;
  private jwtHandler: JWTHandler;
  private sessionCallbacks: SessionCallback[] = [];
  private jwtCallbacks: JWTCallback[] = [];

  // YENİ: Security features
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
      maxAge: 24 * 60 * 60,
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

  // ESKİ metodlarınız (değişmeden kalıyor)
  onSession(callback: SessionCallback): void {
    this.sessionCallbacks.push(callback);
  }

  onJWT(callback: JWTCallback): void {
    this.jwtCallbacks.push(callback);
  }

  // YENİ: Blacklist methods
  async invalidateSession(sessionId: string): Promise<void> {
    if (!this.securityOptions.enableBlacklist) {
      console.warn('Blacklist is not enabled. Enable it in SecurityOptions.');
      return;
    }

    await this.sessionBlacklist.add(sessionId);
    this.log('SESSION_INVALIDATED', { sessionId });
  }

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

  // GÜNCELLENMİŞ: createSession (güvenlik özellikleri eklendi)
  async createSession(
      user: SessionUser,
      data?: SessionData,
      options?: SessionOptions & {
        ipAddress?: string;
        userAgent?: string;
      }
  ): Promise<{ token: string; setCookieHeader: string; session: Session }> {
    if (this.securityOptions.enableRateLimit) {
      const canProceed = await this.rateLimiter.check(`create:${user.id}`);
      if (!canProceed) {
        throw new Error('Rate limit exceeded. Please try again later.');
      }
    }

    if (this.securityOptions.enableBlacklist && this.securityOptions.maxSessionsPerUser) {
      const userSessions = this.activeSessionsByUser.get(user.id) || new Set();
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

    let sessionData = { ...data };
    if (this.securityOptions.enableIpBinding && options?.ipAddress) {
      sessionData = {
        ...sessionData,
        _ipHash: JWTHandler.hash(options.ipAddress),
        _uaHash: options.userAgent ? JWTHandler.hash(options.userAgent) : undefined,
      };
    }

    let payload: SessionPayload = {
      sessionId,
      user,
      iat: now,
      exp: expiresAt,
      data: sessionData,
    };

    for (const callback of this.jwtCallbacks) {
      payload = await callback(payload);
    }

    const token = this.jwtHandler.encode(payload);

    if (this.securityOptions.enableBlacklist) {
      const userSessions = this.activeSessionsByUser.get(user.id) || new Set();
      userSessions.add(sessionId);
      this.activeSessionsByUser.set(user.id, userSessions);
    }

    let session: Session = {
      user,
      expires: expiresAt * 1000,
      data: sessionData,
    };

    for (const callback of this.sessionCallbacks) {
      session = await callback(session);
    }

    const setCookieHeader = this.formatCookie(token, maxAge);

    this.log('SESSION_CREATED', {
      userId: user.id,
      sessionId,
      ipAddress: options?.ipAddress,
    });

    return {
      token,
      setCookieHeader,
      session,
    };
  }

  private formatCookie(token: string, maxAge: number): string {
    let cookieString = `${encodeURIComponent(this.config.cookieName!)}=${encodeURIComponent(token)}`;

    if (maxAge) {
      cookieString += `; Max-Age=${maxAge}`;
      const expiresDate = new Date();
      expiresDate.setSeconds(expiresDate.getSeconds() + maxAge);
      cookieString += `; Expires=${expiresDate.toUTCString()}`;
    }

    cookieString += `; Path=/`;
    cookieString += `; SameSite=${this.config.sameSite}`;
    cookieString += `; HttpOnly`;

    if (this.config.secure) {
      cookieString += '; Secure';
    }

    return cookieString;
  }

  async validateSession(
      cookieString?: string,
      cookieValue?: string,
      options?: {
        ipAddress?: string;
        userAgent?: string;
      }
  ): Promise<Session | null> {
    if (this.securityOptions.enableRateLimit) {
      const rateLimitKey = options?.ipAddress || 'unknown';
      const canProceed = await this.rateLimiter.check(`validate:${rateLimitKey}`);
      if (!canProceed) {
        throw new Error('Too many validation attempts');
      }
    }

    const token = cookieValue || getCookie(this.config.cookieName!, cookieString);

    if (!token) {
      return null;
    }

    const payload = this.jwtHandler.decode(token);

    if (!payload) {
      this.log('SESSION_VALIDATION_FAILED', { error: 'Invalid token' });
      return null;
    }

    if (this.securityOptions.enableBlacklist) {
      const isBlacklisted = await this.sessionBlacklist.has(payload.sessionId);
      if (isBlacklisted) {
        this.log('SESSION_BLACKLISTED', { sessionId: payload.sessionId });
        return null;
      }
    }

    if (payload.exp * 1000 < Date.now()) {
      if (this.securityOptions.enableBlacklist) {
        await this.invalidateSession(payload.sessionId);
      }
      return null;
    }

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

    let session: Session = {
      user: payload.user,
      expires: payload.exp * 1000,
      data: payload.data,
    };

    for (const callback of this.sessionCallbacks) {
      session = await callback(session);
    }

    return session;
  }

  async updateSession(
      user: SessionUser,
      data?: SessionData,
      options?: SessionOptions
  ): Promise<{ token: string; setCookieHeader: string; session: Session }> {
    return this.createSession(user, data, options);
  }

  clearSession(): string {
    return formatClearCookie(this.config.cookieName!);
  }

  getCookieName(): string {
    return this.config.cookieName!;
  }

  async getSessionFromRequest(
      headers?: Record<string, string | string[] | undefined>,
      cookies?: Record<string, string>,
      options?: { ipAddress?: string; userAgent?: string }
  ): Promise<Session | null> {
    let cookieString = '';

    if (headers) {
      const cookieHeader = headers['cookie'] || headers['Cookie'];
      if (typeof cookieHeader === 'string') {
        cookieString = cookieHeader;
      } else if (Array.isArray(cookieHeader)) {
        cookieString = cookieHeader[0];
      }
    }

    if (cookies && cookies[this.config.cookieName!]) {
      return this.validateSession(
          undefined,
          cookies[this.config.cookieName!],
          options
      );
    }

    return this.validateSession(cookieString, undefined, options);
  }

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

export function initializeServer(
    config: NguardConfig,
    securityOptions?: SecurityOptions
): NguardServer {
  return new NguardServer(config, securityOptions);
}