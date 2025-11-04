/**
 * Complete Next.js Middleware Example with Nguard & next-intl
 * Compatible with i18n and authentication
 */

import { createMiddlewareChain, compose, requireAuth, requireRole, logger, cors, onPath } from 'nguard';
import { createIntlMiddleware } from 'next-intl/middleware';
import { NextRequest, NextResponse } from 'next/server';
import { Session } from 'nguard';

// Your supported locales
const LOCALES = ['en', 'tr', 'es'];
const DEFAULT_LOCALE = 'en';

/**
 * Create next-intl middleware
 * This handles i18n routing and locale detection
 */
const intlMiddleware = createIntlMiddleware({
  locales: LOCALES,
  defaultLocale: DEFAULT_LOCALE,
  localePrefix: 'as-needed',
});

/**
 * Step 1: Create your custom Nguard middleware
 * This will be applied after i18n middleware
 */
import { NguardMiddleware } from 'nguard';

const authMiddleware: NguardMiddleware = (request, session) => {
  // Protected paths that require authentication
  const protectedPaths = ['/dashboard', '/profile', '/admin'];
  const pathname = request.nextUrl.pathname;

  // Remove locale from pathname for comparison
  const pathWithoutLocale = pathname.replace(/^\/(en|tr|es)/, '');

  if (protectedPaths.some((p) => pathWithoutLocale.startsWith(p))) {
    if (!session) {
      // Extract locale from URL
      const locale = pathname.match(/^\/(en|tr|es)/)?.[1] || DEFAULT_LOCALE;
      return NextResponse.redirect(new URL(`/${locale}/login`, request.url));
    }
  }
};

/**
 * Step 2: Create role-based middleware
 * Admin routes require admin role
 */
const adminMiddleware: NguardMiddleware = (request, session) => {
  const pathname = request.nextUrl.pathname;
  const pathWithoutLocale = pathname.replace(/^\/(en|tr|es)/, '');

  if (pathWithoutLocale.startsWith('/admin')) {
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const userRole = (session as any).role;
    if (userRole !== 'admin') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
  }
};

/**
 * Step 3: Compose all middleware
 * Order matters: intl → auth → logging → cors
 */
export function middleware(request: NextRequest) {
  // Step 1: Apply i18n middleware first
  const intlResponse = intlMiddleware(request);

  // Step 2: Get session from cookies
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;

  if (sessionCookie) {
    try {
      // Decode JWT if needed, or parse from cookie
      // This is simplified - in production, properly decode JWT
      session = JSON.parse(sessionCookie);
    } catch {
      session = null;
    }
  }

  // Step 3: Create Nguard middleware chain
  const composedMiddleware = compose(
    authMiddleware,
    adminMiddleware,
    logger(),
    cors({
      allowedOrigins: ['http://localhost:3000', 'https://yourdomain.com'],
      credentials: true,
    })
  );

  // Step 4: Apply Nguard middleware
  const authResponse = composedMiddleware(request, session);

  // If auth middleware returned a response, use it
  if (authResponse instanceof Promise) {
    return authResponse.then((res) => {
      // Merge headers from intl and auth responses
      intlResponse.headers.forEach((value, key) => {
        if (res.headers.get(key) === null) {
          res.headers.set(key, value);
        }
      });
      return res;
    });
  }

  if (authResponse instanceof NextResponse) {
    // Merge headers
    authResponse.headers.forEach((value, key) => {
      if (intlResponse.headers.get(key) === null) {
        intlResponse.headers.set(key, value);
      }
    });
    return authResponse;
  }

  // Return intl response if no auth middleware triggered
  return intlResponse;
}

/**
 * Configure which paths the middleware should run on
 * Exclude static files, images, etc.
 */
export const config = {
  matcher: [
    // Match all except:
    '/((?!_next|api|favicon.ico|robots.txt|sitemap.xml).*)',
  ],
};
