/**
 * Simplified app/layout.tsx with Default SessionProvider
 *
 * No need to manually define callbacks!
 * SessionProvider automatically uses:
 * - POST /api/auth/login for login
 * - POST /api/auth/logout for logout
 */

'use client';

import { SessionProvider } from 'nguard/client';
import type { ReactNode } from 'react';

interface RootLayoutProps {
  children: ReactNode;
}

/**
 * Root Layout - Ultra Simple Setup
 *
 * That's it! No callbacks needed.
 */
export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>My App</title>
      </head>
      <body>
        <SessionProvider>
          <header>
            <Header />
          </header>
          <main>
            {children}
          </main>
        </SessionProvider>
      </body>
    </html>
  );
}

/**
 * Header Component - Shows login/logout buttons
 */
'use client';

import { useAuth } from 'nguard/client';
import Link from 'next/link';

function Header() {
  const { user, isAuthenticated, logout, isLoading } = useAuth();

  return (
    <header style={{ display: 'flex', justifyContent: 'space-between', padding: '1rem' }}>
      <Link href="/">
        <h1>My App</h1>
      </Link>

      <nav style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
        {isAuthenticated ? (
          <>
            <span>Welcome, {user?.name || user?.email}</span>
            <button onClick={logout} disabled={isLoading}>
              {isLoading ? 'Logging out...' : 'Logout'}
            </button>
          </>
        ) : (
          <Link href="/login">
            <button>Login</button>
          </Link>
        )}
      </nav>
    </header>
  );
}

// ============================================================================
// PAGES
// ============================================================================

/**
 * Login Page
 * Location: app/login/page.tsx
 */
'use client';

import { useAuth } from 'nguard/client';
import { useRouter } from 'next/navigation';
import { FormEvent, useState } from 'react';

export default function LoginPage() {
  const { login, isLoading } = useAuth();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  async function handleLogin(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);

    const formData = new FormData(e.currentTarget);
    const email = formData.get('email') as string;
    const password = formData.get('password') as string;

    try {
      await login({ email, password });
      router.push('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    }
  }

  return (
    <div style={{ maxWidth: '400px', margin: '2rem auto' }}>
      <h1>Login</h1>

      {error && (
        <div style={{ color: 'red', marginBottom: '1rem' }}>
          {error}
        </div>
      )}

      <form onSubmit={handleLogin}>
        <div style={{ marginBottom: '1rem' }}>
          <label>
            Email:
            <input
              type="email"
              name="email"
              required
              style={{ display: 'block', width: '100%', marginTop: '0.5rem' }}
            />
          </label>
        </div>

        <div style={{ marginBottom: '1rem' }}>
          <label>
            Password:
            <input
              type="password"
              name="password"
              required
              style={{ display: 'block', width: '100%', marginTop: '0.5rem' }}
            />
          </label>
        </div>

        <button
          type="submit"
          disabled={isLoading}
          style={{ width: '100%', padding: '0.5rem' }}
        >
          {isLoading ? 'Logging in...' : 'Login'}
        </button>
      </form>
    </div>
  );
}

/**
 * Dashboard Page (Protected)
 * Location: app/dashboard/page.tsx
 */

import { auth } from '@/lib/auth';
import Link from 'next/link';

export default async function DashboardPage() {
  // Server-side: Get session
  const session = await auth();

  if (!session) {
    return (
      <div>
        <p>Please <Link href="/login">login</Link> first.</p>
      </div>
    );
  }

  return (
    <div style={{ padding: '2rem' }}>
      <h1>Dashboard</h1>

      <div style={{ backgroundColor: '#f0f0f0', padding: '1rem', borderRadius: '4px' }}>
        <h2>Session Info</h2>
        <p><strong>User ID:</strong> {session.user.id}</p>
        <p><strong>Name:</strong> {session.user.name}</p>
        <p><strong>Email:</strong> {session.user.email}</p>
        <p><strong>Role:</strong> {session.data?.role || 'N/A'}</p>
        <p><strong>Expires:</strong> {new Date(session.expires).toLocaleString()}</p>
      </div>

      <div style={{ marginTop: '2rem' }}>
        <h2>Available Actions</h2>
        <ul>
          <li><Link href="/profile">View Profile</Link></li>
          <li><Link href="/settings">Settings</Link></li>
          <li><Link href="/api/auth/session">Check Session (API)</Link></li>
        </ul>
      </div>
    </div>
  );
}

/**
 * Profile Page (Server Component)
 * Location: app/profile/page.tsx
 */

export default async function ProfilePage() {
  const session = await auth();

  if (!session) {
    return <div>Not authenticated</div>;
  }

  return (
    <div style={{ padding: '2rem' }}>
      <h1>Profile</h1>
      <div>
        <p><strong>Name:</strong> {session.user.name}</p>
        <p><strong>Email:</strong> {session.user.email}</p>
        <p><strong>ID:</strong> {session.user.id}</p>
      </div>
    </div>
  );
}

/**
 * Settings Page (Client Component with Update)
 * Location: app/settings/page.tsx
 */

'use client';

import { useAuth, useSessionUpdate } from 'nguard/client';
import { useState } from 'react';

export default function SettingsPage() {
  const { user } = useAuth();
  const { updateSession, isLoading } = useSessionUpdate();
  const [theme, setTheme] = useState<'light' | 'dark'>('light');

  if (!user) {
    return <div>Not authenticated</div>;
  }

  async function handleThemeChange(newTheme: 'light' | 'dark') {
    try {
      // Call API to update preferences
      const res = await fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ theme: newTheme }),
      });

      if (!res.ok) throw new Error('Update failed');

      const data = await res.json();

      // Update session on client
      await updateSession(data.session.user, data.session.data);
      setTheme(newTheme);
    } catch (error) {
      alert('Failed to update settings');
    }
  }

  return (
    <div style={{ padding: '2rem' }}>
      <h1>Settings</h1>

      <div style={{ marginBottom: '2rem' }}>
        <h2>Theme</h2>
        <button
          onClick={() => handleThemeChange('light')}
          disabled={isLoading || theme === 'light'}
        >
          ☀️ Light Mode
        </button>
        <button
          onClick={() => handleThemeChange('dark')}
          disabled={isLoading || theme === 'dark'}
          style={{ marginLeft: '1rem' }}
        >
          🌙 Dark Mode
        </button>
      </div>
    </div>
  );
}

/**
 * Home Page
 * Location: app/page.tsx
 */

export default function HomePage() {
  return (
    <div style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Welcome to My App</h1>
      <p>This app uses Nguard for authentication with default SessionProvider setup.</p>

      <div style={{ backgroundColor: '#f0f0f0', padding: '1rem', borderRadius: '4px', marginTop: '2rem' }}>
        <h2>Getting Started</h2>
        <ol>
          <li>Create <code>app/api/auth/login/route.ts</code> endpoint</li>
          <li>Create <code>app/api/auth/logout/route.ts</code> endpoint</li>
          <li>Create <code>lib/auth.ts</code> with <code>auth()</code> function</li>
          <li>Wrap your app with <code>&lt;SessionProvider&gt;</code> (that's it!)</li>
          <li>Use <code>await auth()</code> in server components</li>
          <li>Use <code>useAuth()</code> hook in client components</li>
        </ol>
      </div>
    </div>
  );
}
