/**
 * Nguard - Main Export
 * Next.js 16 compatible session management library
 */

// Types
export type {
  SessionData,
  SessionUser,
  Session,
  NguardConfig,
  SessionOptions,
  SessionPayload,
  SessionCallback,
  JWTCallback,
} from './types';

// Client Types & Callbacks
export type {
  LoginCallback,
  LogoutCallback,
  InitializeSessionCallback,
  LoginResponse,
  LogoutResponse,
  UpdateSessionResponse,
} from './client';

// Server Types & Callbacks
export type {
  ServerLoginCallback,
  ServerLogoutCallback,
  ValidateSessionCallback,
} from './server';

// Server
export { NguardServer, initializeServer } from './server';

// Client
export {
  SessionProvider,
  useSession,
  useAuth,
  useSessionUpdate,
  useLogin,
  useLogout,
} from './client';

// Middleware
export type {
  NguardMiddleware,
  MiddlewareConfig,
  RateLimitConfig,
  LoggingConfig,
  CORSConfig,
  HeadersConfig,
} from './middleware';

export {
  createMiddlewareChain,
  requireAuth,
  requireRole,
  requirePermission,
  rateLimit,
  logger,
  cors,
  injectHeaders,
  compose,
  withErrorHandling,
  when,
  onPath,
} from './middleware';

// Utilities
export { JWTHandler } from './jwt';
export {
  parseCookies,
  getCookie,
  formatSetCookie,
  formatClearCookie,
  setCookieClient,
  getCookieClient,
  clearCookieClient,
} from './cookies';
