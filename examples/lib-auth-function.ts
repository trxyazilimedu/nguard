/**
 * auth() - Server & Client Session Function (like NextAuth)
 * Location: lib/auth.ts
 *
 * Bu fonksiyon Next Auth'daki gibi çalışır:
 * - Server-side: Sessioni doğrudan al
 * - Client-side: SessionProvider'dan al
 */

import { initializeServer } from 'nguard/server';
import { headers } from 'next/headers';

// ============================================================================
// Nguard Initialization
// ============================================================================

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET!,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'Lax',
  maxAge: 24 * 60 * 60, // 24 hours
});

// ============================================================================
// Session Type Definition
// ============================================================================

export interface Session {
  user: {
    id: string;
    email?: string;
    name?: string;
    [key: string]: any;
  };
  data?: {
    role?: string;
    permissions?: string[];
    [key: string]: any;
  };
  expires: number;
}

// ============================================================================
// Server-Side: auth() function
// ============================================================================

/**
 * Get current session on server-side
 *
 * Usage in Server Components:
 * ```typescript
 * import { auth } from '@/lib/auth';
 *
 * export default async function Dashboard() {
 *   const session = await auth();
 *   if (!session) return <LoginPage />;
 *   return <Dashboard user={session.user} />;
 * }
 * ```
 *
 * Usage in API Routes:
 * ```typescript
 * import { auth } from '@/lib/auth';
 *
 * export async function GET(request: Request) {
 *   const session = await auth();
 *   if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
 *   return Response.json({ user: session.user });
 * }
 * ```
 */
export async function auth(): Promise<Session | null> {
  try {
    const headersList = await headers();
    const cookie = headersList.get('cookie');

    if (!cookie) {
      return null;
    }

    const session = await nguard.validateSession(cookie);
    return session || null;
  } catch (error) {
    console.error('Auth error:', error);
    return null;
  }
}

// ============================================================================
// Helper: Create Session
// ============================================================================

/**
 * Create a new session (used in API routes)
 *
 * Usage:
 * ```typescript
 * const { session, setCookieHeader } = await createSession(
 *   { id: user.id, email: user.email, name: user.name },
 *   { role: user.role, permissions: user.permissions }
 * );
 * ```
 */
export async function createSession(
  user: Session['user'],
  data?: Session['data']
) {
  return await nguard.createSession(user, data);
}

// ============================================================================
// Helper: Validate Session
// ============================================================================

/**
 * Validate a session from cookie string
 *
 * Usage:
 * ```typescript
 * const session = await validateSession(cookieString);
 * ```
 */
export async function validateSession(
  cookieString?: string
): Promise<Session | null> {
  try {
    if (!cookieString) {
      const headersList = await headers();
      cookieString = headersList.get('cookie') || undefined;
    }

    const session = await nguard.validateSession(cookieString);
    return session || null;
  } catch (error) {
    console.error('Validate session error:', error);
    return null;
  }
}

// ============================================================================
// Helper: Clear Session
// ============================================================================

/**
 * Get clear session cookie header (for logout)
 *
 * Usage in API Route:
 * ```typescript
 * export async function POST(request: Request) {
 *   const clearCookie = clearSession();
 *   return Response.json({ ok: true }, {
 *     headers: { 'Set-Cookie': clearCookie }
 *   });
 * }
 * ```
 */
export function clearSession(): string {
  return nguard.clearSession();
}

// ============================================================================
// Helper: Update Session
// ============================================================================

/**
 * Update session with new data
 *
 * Usage:
 * ```typescript
 * const { session, setCookieHeader } = await updateSession(
 *   { ...user, name: 'New Name' },
 *   { role: 'admin' }
 * );
 * ```
 */
export async function updateSession(
  user: Session['user'],
  data?: Session['data']
) {
  return await nguard.updateSession(user, data);
}

// ============================================================================
// Middleware: Protect Routes (Optional)
// ============================================================================

import { NextRequest, NextResponse } from 'next/server';

/**
 * Middleware to protect routes
 *
 * Usage in middleware.ts:
 * ```typescript
 * import { authMiddleware } from '@/lib/auth';
 *
 * export const config = {
 *   matcher: ['/dashboard/:path*', '/admin/:path*']
 * };
 *
 * export default authMiddleware;
 * ```
 */
export async function authMiddleware(request: NextRequest) {
  const session = await validateSession(request.headers.get('cookie') || undefined);

  if (!session) {
    // Redirect to login if no session
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return NextResponse.next();
}

/**
 * Role-based middleware
 *
 * Usage:
 * ```typescript
 * import { withRole } from '@/lib/auth';
 *
 * export const config = {
 *   matcher: ['/admin/:path*']
 * };
 *
 * export default withRole('admin');
 * ```
 */
export function withRole(requiredRole: string) {
  return async (request: NextRequest) => {
    const session = await validateSession(request.headers.get('cookie') || undefined);

    if (!session) {
      return NextResponse.redirect(new URL('/login', request.url));
    }

    if (session.data?.role !== requiredRole) {
      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }

    return NextResponse.next();
  };
}
