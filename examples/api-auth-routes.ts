/**
 * API Routes for Authentication
 * These are the default endpoints that SessionProvider uses
 */

// ============================================================================
// app/api/auth/login/route.ts
// ============================================================================

import { createSession } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

const BACKEND_API_URL = process.env.BACKEND_API_URL!;

/**
 * POST /api/auth/login
 *
 * Default endpoint used by SessionProvider
 * Sends credentials to backend and creates session
 */
export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password required' },
        { status: 400 }
      );
    }

    // Call backend for authentication
    const backendRes = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!backendRes.ok) {
      const error = await backendRes.json();
      return NextResponse.json(
        { error: error.error || 'Authentication failed' },
        { status: 401 }
      );
    }

    // Get user data from backend
    const userData = await backendRes.json();

    // Create session with Nguard
    const { session, setCookieHeader } = await createSession(
      userData.user,
      { role: userData.role, permissions: userData.permissions }
    );

    return NextResponse.json({ session }, {
      status: 200,
      headers: { 'Set-Cookie': setCookieHeader },
    });
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Login failed' },
      { status: 500 }
    );
  }
}

// ============================================================================
// app/api/auth/logout/route.ts
// ============================================================================

import { clearSession, validateSession } from '@/lib/auth';

/**
 * POST /api/auth/logout
 *
 * Default endpoint used by SessionProvider
 * Clears session and notifies backend
 */
export async function POST(request: NextRequest) {
  try {
    // Get current session
    const cookie = request.headers.get('cookie');
    const session = await validateSession(cookie || undefined);

    if (session) {
      // Optionally notify backend
      await fetch(`${BACKEND_API_URL}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: session.user.id }),
      }).catch(err => console.error('Backend logout error:', err));
    }

    // Clear session cookie
    const clearCookie = clearSession();

    return NextResponse.json({ ok: true }, {
      status: 200,
      headers: { 'Set-Cookie': clearCookie },
    });
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json(
      { ok: true }, // Always return ok for logout
      { status: 200 }
    );
  }
}

// ============================================================================
// app/api/auth/session/route.ts
// ============================================================================

import { validateSession } from '@/lib/auth';

/**
 * GET /api/auth/session
 *
 * Optional: Used by SessionProvider if onInitialize is not provided
 * Returns current session from cookie
 */
export async function GET(request: NextRequest) {
  try {
    const cookie = request.headers.get('cookie');
    const session = await validateSession(cookie || undefined);

    if (!session) {
      return NextResponse.json(
        { session: null },
        { status: 401 }
      );
    }

    return NextResponse.json({ session }, { status: 200 });
  } catch (error) {
    console.error('Session error:', error);
    return NextResponse.json(
      { session: null },
      { status: 401 }
    );
  }
}

// ============================================================================
// app/api/auth/update/route.ts
// ============================================================================

import { updateSession, validateSession } from '@/lib/auth';

/**
 * POST /api/auth/update
 *
 * Update user preferences (theme, language, etc.)
 * Used by useSessionUpdate() hook
 */
export async function POST(request: NextRequest) {
  try {
    // Validate current session
    const cookie = request.headers.get('cookie');
    const session = await validateSession(cookie || undefined);

    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const updateData = await request.json();

    // Send update to backend
    const backendRes = await fetch(`${BACKEND_API_URL}/users/${session.user.id}/preferences`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updateData),
    });

    if (!backendRes.ok) {
      const error = await backendRes.json();
      return NextResponse.json(
        { error: error.error || 'Update failed' },
        { status: backendRes.status }
      );
    }

    // Create new session with updated data
    const { session: newSession, setCookieHeader } = await updateSession(
      session.user,
      {
        ...session.data,
        ...updateData,
      }
    );

    return NextResponse.json({ session: newSession }, {
      status: 200,
      headers: { 'Set-Cookie': setCookieHeader },
    });
  } catch (error) {
    console.error('Update error:', error);
    return NextResponse.json(
      { error: 'Update failed' },
      { status: 500 }
    );
  }
}

// ============================================================================
// app/api/auth/update-role/route.ts
// ============================================================================

/**
 * POST /api/auth/update-role
 *
 * Update user role (admin only)
 * Called by admin panel to change user roles
 */
export async function POST(request: NextRequest) {
  try {
    const cookie = request.headers.get('cookie');
    const session = await validateSession(cookie || undefined);

    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Check if admin
    if (session.data?.role !== 'admin') {
      return NextResponse.json(
        { error: 'Only admins can change roles' },
        { status: 403 }
      );
    }

    const { userId, newRole } = await request.json();

    // Send to backend
    const backendRes = await fetch(`${BACKEND_API_URL}/users/${userId}/role`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: newRole }),
    });

    if (!backendRes.ok) {
      const error = await backendRes.json();
      return NextResponse.json(
        { error: error.error || 'Update failed' },
        { status: backendRes.status }
      );
    }

    const userData = await backendRes.json();

    return NextResponse.json({
      success: true,
      user: userData.user,
    }, { status: 200 });
  } catch (error) {
    console.error('Role update error:', error);
    return NextResponse.json(
      { error: 'Update failed' },
      { status: 500 }
    );
  }
}
