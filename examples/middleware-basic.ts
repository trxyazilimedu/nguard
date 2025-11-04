/**
 * Basic Nguard Middleware Examples
 * Simple patterns for common use cases
 */

import {
  requireAuth,
  requireRole,
  requirePermission,
  logger,
  rateLimit,
  compose,
  onPath,
  when,
} from 'nguard';
import { NextRequest, NextResponse } from 'next/server';
import { Session } from 'nguard';

/**
 * Example 1: Basic authentication middleware
 * Protect all /dashboard routes
 */
export function basicAuthMiddleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Get session from cookies
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;

  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {
      session = null;
    }
  }

  // Apply middleware
  const middleware = requireAuth();
  const response = middleware(request, session);

  if (response instanceof NextResponse) {
    return response;
  }

  return NextResponse.next();
}

/**
 * Example 2: Role-based access control
 * Only admins can access /admin routes
 */
export function roleBasedMiddleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;

  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {
      session = null;
    }
  }

  // Check if path is admin route
  if (request.nextUrl.pathname.startsWith('/admin')) {
    const middleware = requireRole('admin');
    const response = middleware(request, session);

    if (response instanceof NextResponse) {
      return response;
    }
  }

  return NextResponse.next();
}

/**
 * Example 3: Permission-based access control
 * Check specific permissions
 */
export function permissionBasedMiddleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;

  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {
      session = null;
    }
  }

  // Check route-specific permissions
  const routePermissions: Record<string, string[]> = {
    '/api/users': ['users:read'],
    '/api/users/create': ['users:create'],
    '/api/users/delete': ['users:delete'],
  };

  const pathname = request.nextUrl.pathname;
  const requiredPermissions = routePermissions[pathname];

  if (requiredPermissions) {
    const middleware = requirePermission(requiredPermissions);
    const response = middleware(request, session);

    if (response instanceof NextResponse) {
      return response;
    }
  }

  return NextResponse.next();
}

/**
 * Example 4: Composed middleware with logging and rate limiting
 */
export async function composedMiddleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;

  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {
      session = null;
    }
  }

  // Compose multiple middleware
  const middleware = compose(
    // Log all requests
    logger({
      onLog: (data) => {
        console.log(`[${data.timestamp}] ${data.method} ${data.pathname}`);
      },
    }),
    // Rate limit: 100 requests per minute
    rateLimit({
      maxRequests: 100,
      windowMs: 60 * 1000,
    }),
    // Require auth for protected paths
    onPath(/^\/api\/protected/, requireAuth()),
    // Require admin for admin paths
    onPath(/^\/admin/, requireRole('admin'))
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}

/**
 * Example 5: Conditional middleware
 * Apply different middleware based on conditions
 */
export function conditionalMiddleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;

  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {
      session = null;
    }
  }

  // Different rules for different environments
  const isProduction = process.env.NODE_ENV === 'production';

  const middleware = when(
    (req) => isProduction,
    compose(
      // Stricter rate limiting in production
      rateLimit({
        maxRequests: 50,
        windowMs: 60 * 1000,
      }),
      // Require auth for more paths in production
      requireAuth()
    )
  );

  const response = middleware(request, session);

  if (response instanceof NextResponse) {
    return response;
  }

  return NextResponse.next();
}

/**
 * Example 6: Custom middleware
 * Create your own middleware for specific needs
 */
import { NguardMiddleware } from 'nguard';

const customLoggingMiddleware: NguardMiddleware = (request, session) => {
  const start = Date.now();

  // Middleware logic
  console.log({
    method: request.method,
    pathname: request.nextUrl.pathname,
    userId: (session as any)?.id,
    timestamp: new Date().toISOString(),
  });

  // You can return a NextResponse to modify behavior
  // or return nothing to continue
  const response = NextResponse.next();

  // Add custom header
  response.headers.set('X-Response-Time', `${Date.now() - start}ms`);
  return response;
};

export function customMiddleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;

  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {
      session = null;
    }
  }

  return customLoggingMiddleware(request, session);
}

/**
 * Configuration for middleware matcher
 * Place this in middleware.ts
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public (public folder)
     */
    '/((?!api|_next/static|_next/image|favicon.ico|public).*)',
  ],
};
