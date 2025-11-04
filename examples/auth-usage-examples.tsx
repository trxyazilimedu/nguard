/**
 * Auth Usage Examples - Both Server and Client Side
 *
 * Showing how to use auth() function and SessionProvider together
 */

// ============================================================================
// SERVER-SIDE EXAMPLES
// ============================================================================

// ============================================================================
// 1. Server Component - Get Session
// ============================================================================

import { auth } from '@/lib/auth';

export default async function Dashboard() {
  // Server-side: Call auth() function (like NextAuth)
  const session = await auth();

  if (!session) {
    return <div>Please login first</div>;
  }

  return (
    <div>
      <h1>Welcome, {session.user.name}</h1>
      <p>Email: {session.user.email}</p>
      <p>Role: {session.data?.role}</p>

      {/* Pass to client component */}
      <ClientComponent user={session.user} />
    </div>
  );
}

// ============================================================================
// 2. API Route - Protect Endpoint
// ============================================================================

import { auth } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  // Validate session
  const session = await auth();

  if (!session) {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    );
  }

  // Check role
  if (session.data?.role !== 'admin') {
    return NextResponse.json(
      { error: 'Forbidden' },
      { status: 403 }
    );
  }

  // Authenticated and authorized
  return NextResponse.json({
    message: 'Admin access granted',
    user: session.user
  });
}

// ============================================================================
// 3. API Route - Login Endpoint
// ============================================================================

import { createSession } from '@/lib/auth';

const BACKEND_API_URL = process.env.BACKEND_API_URL!;

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    // 1. Call backend for authentication
    const backendRes = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!backendRes.ok) {
      throw new Error('Authentication failed');
    }

    const userData = await backendRes.json();

    // 2. Create session with Nguard
    const { session, setCookieHeader } = await createSession(
      userData.user,
      { role: userData.role }
    );

    // 3. Return session with Set-Cookie header
    return NextResponse.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Login failed' },
      { status: 401 }
    );
  }
}

// ============================================================================
// 4. API Route - Logout Endpoint
// ============================================================================

import { clearSession, validateSession } from '@/lib/auth';

export async function POST(request: NextRequest) {
  try {
    // Get current session
    const session = await validateSession(
      request.headers.get('cookie') || undefined
    );

    if (session) {
      // Optionally call backend for cleanup
      await fetch(`${BACKEND_API_URL}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: session.user.id })
      }).catch(err => console.error('Backend logout error:', err));
    }

    // Clear cookie
    const clearCookie = clearSession();

    return NextResponse.json({ ok: true }, {
      headers: { 'Set-Cookie': clearCookie }
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Logout failed' },
      { status: 500 }
    );
  }
}

// ============================================================================
// CLIENT-SIDE EXAMPLES
// ============================================================================

'use client';

import { useAuth } from 'nguard/client';
import { useSessionUpdate } from 'nguard/client';

// ============================================================================
// 1. Client Component - Get User
// ============================================================================

export function UserProfile() {
  const { user, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <div>Not logged in</div>;
  }

  return (
    <div>
      <h1>{user?.name}</h1>
      <p>{user?.email}</p>
    </div>
  );
}

// ============================================================================
// 2. Client Component - Login Form
// ============================================================================

export function LoginForm() {
  const { login, isLoading } = useAuth();

  async function handleLogin(formData: FormData) {
    try {
      await login({
        email: formData.get('email'),
        password: formData.get('password')
      });
    } catch (error) {
      alert('Login failed');
    }
  }

  return (
    <form action={handleLogin}>
      <input
        type="email"
        name="email"
        placeholder="Email"
        required
      />
      <input
        type="password"
        name="password"
        placeholder="Password"
        required
      />
      <button disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}

// ============================================================================
// 3. Client Component - Update Session
// ============================================================================

export function UpdateRoleButton() {
  const { user } = useAuth();
  const { updateSession, isLoading } = useSessionUpdate();

  async function handleUpdate() {
    if (!user) return;

    try {
      // Call API to update role
      const res = await fetch('/api/auth/update-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id, newRole: 'admin' })
      });

      if (!res.ok) throw new Error('Update failed');

      const data = await res.json();

      // Update session in client
      await updateSession(data.user, data.data);
    } catch (error) {
      alert('Failed to update role');
    }
  }

  return (
    <button onClick={handleUpdate} disabled={isLoading}>
      {isLoading ? 'Updating...' : 'Make Admin'}
    </button>
  );
}

// ============================================================================
// 4. Client Component - Logout
// ============================================================================

export function LogoutButton() {
  const { logout, isLoading } = useAuth();

  return (
    <button onClick={logout} disabled={isLoading}>
      {isLoading ? 'Logging out...' : 'Logout'}
    </button>
  );
}

// ============================================================================
// LAYOUT SETUP
// ============================================================================

'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback = async (credentials) => {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials)
  });

  if (!res.ok) throw new Error('Login failed');
  const data = await res.json();
  return {
    user: data.session.user,
    data: data.session.data
  };
};

const handleLogout = async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
};

const handleInitialize = async () => {
  try {
    const res = await fetch('/api/auth/session');
    if (res.ok) {
      const data = await res.json();
      return data.session;
    }
  } catch (error) {
    console.error('Initialize error:', error);
  }
  return null;
};

export function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <body>
        <SessionProvider
          onLogin={handleLogin}
          onLogout={handleLogout}
          onInitialize={handleInitialize}
        >
          {children}
        </SessionProvider>
      </body>
    </html>
  );
}
