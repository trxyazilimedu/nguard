/**
 * Nguard - Next.js Session Management Library
 * Types definitions
 */

export interface SessionData {
  [key: string]: any;
}

export interface SessionUser {
  id: string;
  email?: string;
  name?: string;
  [key: string]: any;
}

export interface Session {
  user: SessionUser;
  expires: number;
  data?: SessionData;
}

export interface NguardConfig {
  secret: string;
  cookieName?: string;
  cookiePath?: string;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  maxAge?: number; // seconds
  signed?: boolean;
}

export interface SessionOptions {
  maxAge?: number; // seconds, default 24 hours
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  signed?: boolean;
}

export interface SessionPayload {
  sessionId: string;
  user: SessionUser;
  iat: number;
  exp: number;
  data?: SessionData;
}

export type SessionCallback = (session: Session) => Promise<Session> | Session;
export type JWTCallback = (token: SessionPayload) => Promise<SessionPayload> | SessionPayload;
