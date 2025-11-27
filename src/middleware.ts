/**
 * Nguard - Middleware system for Next.js
 * Flexible composition pattern compatible with next-intl and other middleware
 */

import { NextRequest, NextResponse } from 'next/server';
import { Session } from './types';

/**
 * Middleware function type
 * Each middleware receives the request and can modify the response
 * Compatible with Next.js middleware chain pattern
 */
export type NguardMiddleware = (
  request: NextRequest,
  session: Session | null
) => NextResponse | Promise<NextResponse | void> | void;

/**
 * Middleware configuration
 */
export interface MiddlewareConfig {
  handlers: NguardMiddleware[];
  publicPaths?: string[];
  protectedPaths?: string[];
}

/**
 * Create a composable middleware chain
 * Works with next-intl and other middleware by returning NextResponse
 */
export function createMiddlewareChain(config: MiddlewareConfig): NguardMiddleware {
  return async (
    request: NextRequest,
    session: Session | null
  ) => {
    let response: NextResponse | void = undefined;

    // Execute middleware in sequence
    for (const handler of config.handlers) {
      const result = await handler(request, session);
      if (result instanceof NextResponse) {
        response = result;
        break; // Stop if middleware returns response
      }
    }

    return response;
  };
}

/**
 * Authentication middleware - Require valid session
 */
export interface RequireAuthConfig {
  redirectTo?: string;
}

export const requireAuth = (config?: RequireAuthConfig): NguardMiddleware => {
  const redirectTo: string = config?.redirectTo ?? '/login';

  return (request: NextRequest, session: Session | null) => {
    if (!session) {
      return NextResponse.redirect(new URL(redirectTo, request.url));
    }
  };
};

/**
 * Role-based access control middleware
 */
export interface RequireRoleConfig {
  roles: string | string[];
  redirectTo?: string;
}

export const requireRole = (config: RequireRoleConfig | string | string[]): NguardMiddleware => {
  // Support both legacy format (direct roles) and new config format
  const roles = typeof config === 'object' && 'roles' in config ? config.roles : config;
  const redirectTo: string = typeof config === 'object' && 'redirectTo' in config ? (config.redirectTo ?? '/login') : '/login';
  const roleList = Array.isArray(roles) ? roles : [roles];

  return (request: NextRequest, session: Session | null) => {
    if (!session) {
      return NextResponse.redirect(new URL(redirectTo, request.url));
    }

    // Check if session has role field
    const sessionRole = (session as any).role;
    if (!sessionRole || !roleList.includes(sessionRole)) {
      return NextResponse.json(
        { error: 'Insufficient permissions' },
        { status: 403 }
      );
    }
  };
};

/**
 * Permission-based access control middleware
 */
export interface RequirePermissionConfig {
  permissions: string | string[];
  redirectTo?: string;
}

export const requirePermission = (
  config: RequirePermissionConfig | string | string[]
): NguardMiddleware => {
  // Support both legacy format (direct permissions) and new config format
  const permissions = typeof config === 'object' && 'permissions' in config ? config.permissions : config;
  const redirectTo: string = typeof config === 'object' && 'redirectTo' in config ? (config.redirectTo ?? '/login') : '/login';
  const permissionList = Array.isArray(permissions) ? permissions : [permissions];

  return (request: NextRequest, session: Session | null) => {
    if (!session) {
      return NextResponse.redirect(new URL(redirectTo, request.url));
    }

    // Check if session has permissions field
    const sessionPermissions = (session as any).permissions as string[];
    if (!sessionPermissions || !Array.isArray(sessionPermissions)) {
      return NextResponse.json(
        { error: 'Insufficient permissions' },
        { status: 403 }
      );
    }

    const hasPermission = permissionList.some((p) =>
      sessionPermissions.includes(p)
    );

    if (!hasPermission) {
      return NextResponse.json(
        { error: 'Insufficient permissions' },
        { status: 403 }
      );
    }
  };
};

/**
 * Rate limiting middleware
 * Tracks requests per user/IP
 */
export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number; // milliseconds
}

const rateLimitStore = new Map<string, number[]>();

export const rateLimit = (config: RateLimitConfig): NguardMiddleware => {
  return (request: NextRequest, session: Session | null) => {
    // Use user ID if authenticated, otherwise use IP from headers
    const identifier = session
      ? (session as any).id
      : request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';

    const key = `rate-limit:${identifier}`;
    const now = Date.now();
    const requests = (rateLimitStore.get(key) || []).filter(
      (timestamp) => now - timestamp < config.windowMs
    );

    if (requests.length >= config.maxRequests) {
      return NextResponse.json(
        { error: 'Too many requests' },
        { status: 429 }
      );
    }

    requests.push(now);
    rateLimitStore.set(key, requests);

    // Cleanup old entries periodically
    if (Math.random() < 0.01) {
      for (const [k, v] of rateLimitStore.entries()) {
        const filtered = v.filter((timestamp) => now - timestamp < config.windowMs);
        if (filtered.length === 0) {
          rateLimitStore.delete(k);
        } else {
          rateLimitStore.set(k, filtered);
        }
      }
    }
  };
};

/**
 * Request logging middleware
 * Logs requests to console or custom handler
 */
export interface LoggingConfig {
  onLog?: (data: {
    method: string;
    pathname: string;
    sessionId?: string;
    timestamp: string;
  }) => void;
}

export const logger = (config: LoggingConfig = {}): NguardMiddleware => {
  return (request: NextRequest, session: Session | null) => {
    const data = {
      method: request.method,
      pathname: request.nextUrl.pathname,
      sessionId: (session as any)?.id,
      timestamp: new Date().toISOString(),
    };

    if (config.onLog) {
      config.onLog(data);
    } else {
      console.log('[Nguard]', data);
    }
  };
};

/**
 * CORS middleware
 * Add CORS headers to response
 */
export interface CORSConfig {
  allowedOrigins?: string[];
  allowedMethods?: string[];
  allowedHeaders?: string[];
  exposedHeaders?: string[];
  credentials?: boolean;
  maxAge?: number;
}

export const cors = (config: CORSConfig = {}): NguardMiddleware => {
  return (request: NextRequest) => {
    const response = NextResponse.next();
    const origin = request.headers.get('origin');

    // Check if origin is allowed
    const allowedOrigins = config.allowedOrigins || ['*'];
    if (
      allowedOrigins.includes('*') ||
      (origin && allowedOrigins.includes(origin))
    ) {
      response.headers.set('Access-Control-Allow-Origin', origin || '*');
    }

    response.headers.set(
      'Access-Control-Allow-Methods',
      config.allowedMethods?.join(',') || 'GET, POST, PUT, DELETE, PATCH'
    );

    response.headers.set(
      'Access-Control-Allow-Headers',
      config.allowedHeaders?.join(',') || 'Content-Type, Authorization'
    );

    if (config.exposedHeaders) {
      response.headers.set(
        'Access-Control-Expose-Headers',
        config.exposedHeaders.join(',')
      );
    }

    if (config.credentials) {
      response.headers.set('Access-Control-Allow-Credentials', 'true');
    }

    if (config.maxAge) {
      response.headers.set('Access-Control-Max-Age', config.maxAge.toString());
    }

    return response;
  };
};

/**
 * Custom header injection middleware
 */
export interface HeadersConfig {
  [key: string]: string;
}

export const injectHeaders = (headers: HeadersConfig): NguardMiddleware => {
  return (_request: NextRequest) => {
    const response = NextResponse.next();

    for (const [key, value] of Object.entries(headers)) {
      response.headers.set(key, value);
    }

    return response;
  };
};

/**
 * Compose multiple middleware into a single middleware
 * Compatible with Next.js middleware and next-intl
 */
export function compose(...middlewares: NguardMiddleware[]) {
  return async (
    request: NextRequest,
    session: Session | null
  ): Promise<NextResponse> => {
    let response = NextResponse.next();

    for (const middleware of middlewares) {
      const result = await middleware(request, session);
      if (result instanceof NextResponse) {
        response = result;
      }
    }

    return response;
  };
}

/**
 * Create middleware with error handling
 */
export function withErrorHandling(
  middleware: NguardMiddleware,
  onError?: (error: Error) => NextResponse
): NguardMiddleware {
  return async (request: NextRequest, session: Session | null) => {
    try {
      return await middleware(request, session);
    } catch (error) {
      if (onError) {
        return onError(error as Error);
      }

      console.error('[Nguard Middleware Error]', error);
      return NextResponse.json(
        { error: 'Internal server error' },
        { status: 500 }
      );
    }
  };
}

/**
 * Conditional middleware execution
 */
export function when(
  condition: (request: NextRequest) => boolean,
  middleware: NguardMiddleware
): NguardMiddleware {
  return (request: NextRequest, session: Session | null) => {
    if (condition(request)) {
      return middleware(request, session);
    }
  };
}

/**
 * Path-based middleware execution
 * Useful for applying different middleware to different routes
 */
export function onPath(
  pathMatcher: string | RegExp | ((pathname: string) => boolean),
  middleware: NguardMiddleware
): NguardMiddleware {
  return (request: NextRequest, session: Session | null) => {
    const pathname = request.nextUrl.pathname;
    let matches = false;

    if (typeof pathMatcher === 'string') {
      matches = pathname === pathMatcher;
    } else if (pathMatcher instanceof RegExp) {
      matches = pathMatcher.test(pathname);
    } else if (typeof pathMatcher === 'function') {
      matches = pathMatcher(pathname);
    }

    if (matches) {
      return middleware(request, session);
    }
  };
}
