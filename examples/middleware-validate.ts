/**
 * Validation Middleware Examples
 * Check session validity in middleware
 */

import { NextRequest, NextResponse } from 'next/server';
import { Session } from 'nguard';
import { NguardMiddleware } from 'nguard';

/**
 * Validate session middleware
 * Checks if session is valid and not expired
 */
export const validateSession: NguardMiddleware = (request, session) => {
  // Skip validation for public routes
  const publicPaths = ['/login', '/register', '/forgot-password'];
  if (publicPaths.some((p) => request.nextUrl.pathname.startsWith(p))) {
    return;
  }

  // If no session, allow (other middleware can require auth)
  if (!session) {
    return;
  }

  // Check if session is expired
  const now = Date.now();
  const expiresAt = (session as any).expires || 0;

  if (expiresAt < now) {
    // Redirect to login if session expired
    return NextResponse.redirect(new URL('/login?expired=true', request.url));
  }

  // Warning: Session expiring soon (within 5 minutes)
  const warningThreshold = 5 * 60 * 1000; // 5 minutes
  if (expiresAt - now < warningThreshold) {
    // Add header to indicate session is expiring soon
    const response = NextResponse.next();
    response.headers.set('X-Session-Expiring', 'true');
    response.headers.set(
      'X-Session-Expires-In',
      Math.ceil((expiresAt - now) / 1000).toString()
    );
    return response;
  }
};

/**
 * Strict validation middleware
 * Requires valid session and specific claims
 */
export const strictValidation = (requiredClaims?: string[]): NguardMiddleware => {
  return (request, session) => {
    // Must have session
    if (!session) {
      return NextResponse.json(
        { error: 'No session' },
        { status: 401 }
      );
    }

    // Check expiration
    const now = Date.now();
    if ((session as any).expires && (session as any).expires < now) {
      return NextResponse.json(
        { error: 'Session expired' },
        { status: 401 }
      );
    }

    // Check required claims
    if (requiredClaims && Array.isArray(requiredClaims)) {
      for (const claim of requiredClaims) {
        if (!(session as any)[claim]) {
          return NextResponse.json(
            { error: `Missing required claim: ${claim}` },
            { status: 403 }
          );
        }
      }
    }
  };
};

/**
 * Validate endpoint middleware
 * For /api/auth/validate endpoint
 * Doesn't require authentication - validates and returns status
 */
export const validateEndpoint: NguardMiddleware = async (request, session) => {
  // Only for validate endpoint
  if (!request.nextUrl.pathname.includes('/api/auth/validate')) {
    return;
  }

  // If no session, return not valid
  if (!session) {
    return NextResponse.json({
      valid: false,
      error: 'No session',
    });
  }

  // Check expiration
  const now = Date.now();
  const expiresAt = (session as any).expires || 0;

  if (expiresAt < now) {
    return NextResponse.json({
      valid: false,
      error: 'Session expired',
      expiresIn: expiresAt - now,
    });
  }

  // Return validation success
  return NextResponse.json({
    valid: true,
    session: {
      id: (session as any).id,
      email: (session as any).email,
      role: (session as any).role,
      permissions: (session as any).permissions,
    },
    expiresIn: expiresAt - now,
  });
};

/**
 * Session status middleware
 * Adds session status information to response headers
 */
export const sessionStatus: NguardMiddleware = (request, session) => {
  const response = NextResponse.next();

  if (!session) {
    response.headers.set('X-Session-Status', 'none');
    return response;
  }

  const now = Date.now();
  const expiresAt = (session as any).expires || 0;

  if (expiresAt < now) {
    response.headers.set('X-Session-Status', 'expired');
    return response;
  }

  const expiresIn = expiresAt - now;
  const warningThreshold = 5 * 60 * 1000;

  if (expiresIn < warningThreshold) {
    response.headers.set('X-Session-Status', 'expiring');
  } else {
    response.headers.set('X-Session-Status', 'valid');
  }

  response.headers.set('X-Session-Expires-In', Math.ceil(expiresIn / 1000).toString());
  response.headers.set('X-User-ID', (session as any).id || 'unknown');

  return response;
};

/**
 * Auto-refresh middleware
 * Automatically refresh session before expiration
 * Requires /api/auth/refresh endpoint
 */
export const autoRefresh = (
  refreshThreshold: number = 5 * 60 * 1000 // 5 minutes before expiration
): NguardMiddleware => {
  return async (request, session) => {
    if (!session) return;

    const now = Date.now();
    const expiresAt = (session as any).expires || 0;
    const expiresIn = expiresAt - now;

    // If session expires within threshold, trigger refresh
    if (expiresIn > 0 && expiresIn < refreshThreshold) {
      // Add header to indicate refresh should be triggered
      const response = NextResponse.next();
      response.headers.set('X-Refresh-Session', 'true');
      return response;
    }
  };
};

/**
 * Usage Example in middleware.ts:
 *
 * import { compose, onPath } from 'nguard';
 * import { validateSession, autoRefresh, sessionStatus } from '@/middleware/validate';
 *
 * export async function middleware(request: NextRequest) {
 *   const session = getSessionFromCookie(request);
 *
 *   const middleware = compose(
 *     validateSession,
 *     autoRefresh(5 * 60 * 1000),
 *     sessionStatus,
 *     onPath('/api/auth/validate', validateEndpoint)
 *   );
 *
 *   const response = await middleware(request, session);
 *   return response || NextResponse.next();
 * }
 */
