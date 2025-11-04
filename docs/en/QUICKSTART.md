# Nguard Quick Start

After running the CLI setup wizard, here's how to use Nguard hooks and authentication in your application.

> **Setup:** Already done by `npx nguard-setup`. For detailed setup guide, see [CLI-SETUP.md](./CLI-SETUP.md)

## Session Provider (app/layout.tsx)

Wrap your app with SessionProvider (zero-config, no callbacks needed):

```typescript
'use client';

import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <SessionProvider>{children}</SessionProvider>
      </body>
    </html>
  );
}
```

The SessionProvider automatically:
- Calls `POST /api/auth/login` for login
- Calls `POST /api/auth/logout` for logout
- Manages session state

## Getting Session

### In Server Components

```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();

  if (!session) {
    return <div>Please log in first</div>;
  }

  return <div>Welcome, {session.email}</div>;
}
```

### In Client Components

```typescript
'use client';

import { useSession } from 'nguard/client';

export function Profile() {
  const { session, loading } = useSession();

  if (loading) return <div>Loading...</div>;
  if (!session) return <div>Not logged in</div>;

  return <div>Welcome, {session.email}</div>;
}
```

## Login & Logout

### useLogin Hook

```typescript
'use client';

import { useLogin } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useLogin();

  async function handleLogin(email: string, password: string) {
    const response = await login({ email, password });

    if (response.session) {
      // Successfully logged in
      console.log('Logged in as:', response.session.email);
    } else if (response.error) {
      // Login failed
      console.error('Login error:', response.error);
    }
  }

  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      const formData = new FormData(e.currentTarget);
      handleLogin(
        formData.get('email') as string,
        formData.get('password') as string
      );
    }}>
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}
```

### useLogout Hook

```typescript
'use client';

import { useLogout } from 'nguard/client';

export function LogoutButton() {
  const { logout, isLoading } = useLogout();

  return (
    <button onClick={logout} disabled={isLoading}>
      {isLoading ? 'Logging out...' : 'Logout'}
    </button>
  );
}
```

## Update Session

The `useSessionUpdate` hook allows updating session data without re-login:

```typescript
'use client';

import { useSessionUpdate } from 'nguard/client';

export function UpdateProfile() {
  const { updateSession, isLoading } = useSessionUpdate();

  async function handleUpdateRole() {
    // Call your API that updates session
    const response = await fetch('/api/user/update-role', {
      method: 'POST',
      body: JSON.stringify({ role: 'admin' }),
    });

    if (response.ok) {
      const data = await response.json();

      // Update the session with new data
      await updateSession(data.session);
    }
  }

  return (
    <button onClick={handleUpdateRole} disabled={isLoading}>
      Update Role
    </button>
  );
}
```

## Validate Session

Check if the current session is valid:

```typescript
'use client';

import { useValidateSession } from 'nguard/client';

export function CheckSession() {
  const { validate, validationResult, isValid } = useValidateSession();

  return (
    <div>
      <button onClick={() => validate()}>Check Session</button>

      {isValid && (
        <p>
          ✅ Session valid
          {validationResult?.expiresIn && (
            <span> - Expires in {Math.round(validationResult.expiresIn / 1000)}s</span>
          )}
        </p>
      )}

      {!isValid && validationResult?.error && (
        <p>❌ {validationResult.error}</p>
      )}
    </div>
  );
}
```

## Error Handling

All login/logout methods return responses instead of throwing errors:

```typescript
'use client';

import { useState } from 'react';
import { useLogin } from 'nguard/client';

export function SmartLoginForm() {
  const { login, isLoading } = useLogin();
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleLogin(email: string, password: string) {
    setMessage(null);
    setError(null);

    try {
      const response = await login({ email, password });

      // Check your API response structure
      if (response.session) {
        setMessage('Login successful!');
      } else if (response.error) {
        setError(response.error);
      }
    } catch (err) {
      // Network or fetch errors
      setError('Network error: ' + (err instanceof Error ? err.message : 'Unknown error'));
    }
  }

  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      const fd = new FormData(e.currentTarget);
      handleLogin(fd.get('email') as string, fd.get('password') as string);
    }}>
      {message && <div className="success">{message}</div>}
      {error && <div className="error">{error}</div>}

      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button disabled={isLoading}>{isLoading ? 'Loading...' : 'Login'}</button>
    </form>
  );
}
```

## useAuth Hook (Legacy Alternative)

If you prefer the `useAuth` hook that returns more properties:

```typescript
'use client';

import { useAuth } from 'nguard/client';

export function AuthComponent() {
  const { session, isAuthenticated, login, logout, isLoading } = useAuth();

  if (!isAuthenticated) {
    return <LoginForm onLogin={login} />;
  }

  return (
    <div>
      <p>Logged in as: {session?.email}</p>
      <button onClick={logout} disabled={isLoading}>Logout</button>
    </div>
  );
}
```

## Custom Session Callbacks (Optional)

If you need custom behavior, you can pass callbacks to SessionProvider:

```typescript
'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback = async (credentials) => {
  // Use custom endpoint
  const res = await fetch('/custom/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });

  return await res.json();
};

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <SessionProvider onLogin={handleLogin}>
          {children}
        </SessionProvider>
      </body>
    </html>
  );
}
```

## Best Practices

1. **Always use SessionProvider** at the root level (app/layout.tsx)
2. **Get session in Server Components** when possible (better for SEO)
3. **Handle loading and error states** in client components
4. **Check session before rendering protected content**
5. **Use hooks for dynamic operations** (login, logout, update)
6. **Validate session on app load** with `useValidateSession`

## API Response Structure

Your backend determines the response format. Nguard returns whatever your API returns:

```typescript
// Your API could return any structure
await login({ email: 'user@example.com', password: 'pass' });

// Possible responses:
{
  session: { id: '123', email: 'user@example.com', role: 'admin' }
}

// Or with status message:
{
  success: true,
  message: 'Logged in successfully',
  session: { /* ... */ }
}

// Or with error:
{
  success: false,
  error: 'Invalid credentials'
}
```

## See Also

- [CLI Setup Guide](./CLI-SETUP.md) - Setup wizard guide
- [API Reference](./API-CLIENT.md) - All available hooks
- [Middleware Guide](./MIDDLEWARE.md) - Add authentication middleware
- [Session Validation](./VALIDATION.md) - Validate session patterns
