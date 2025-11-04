# Quick Start

After running `npx nguard-setup`, here's how to use Nguard.

## Setup SessionProvider

Wrap your app with SessionProvider in `app/layout.tsx`:

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

## Get Session in Server Components

```typescript
// app/dashboard/page.tsx
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();

  if (!session) {
    return <div>Please log in</div>;
  }

  return (
    <div>
      <h1>Hello {session.email}</h1>
      <p>Role: {session.role}</p>
    </div>
  );
}
```

## Get Session in Client Components

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

## Login

```typescript
'use client';

import { useLogin } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useLogin();

  async function handleSubmit(e) {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);

    const response = await login({
      email: formData.get('email'),
      password: formData.get('password'),
    });

    if (response.session) {
      console.log('Logged in!');
    } else if (response.error) {
      console.error('Error:', response.error);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button disabled={isLoading}>
        {isLoading ? 'Loading...' : 'Login'}
      </button>
    </form>
  );
}
```

## Logout

```typescript
'use client';

import { useLogout } from 'nguard/client';

export function LogoutButton() {
  const { logout, isLoading } = useLogout();

  return (
    <button onClick={logout} disabled={isLoading}>
      {isLoading ? 'Loading...' : 'Logout'}
    </button>
  );
}
```

## Update Session

```typescript
'use client';

import { useSessionUpdate } from 'nguard/client';

export function UpdateRole() {
  const { updateSession, isLoading } = useSessionUpdate();

  async function handleUpdate() {
    // Get new session data from your API
    const response = await fetch('/api/user/update-role', {
      method: 'POST',
      body: JSON.stringify({ role: 'admin' }),
    });

    if (response.ok) {
      const data = await response.json();
      await updateSession(data.session);
    }
  }

  return (
    <button onClick={handleUpdate} disabled={isLoading}>
      Update Role
    </button>
  );
}
```

## Validate Session

```typescript
'use client';

import { useValidateSession } from 'nguard/client';

export function CheckSession() {
  const { validate, isValid, validationResult } = useValidateSession();

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

All login/logout methods return responses with error info:

```typescript
'use client';

import { useState } from 'react';
import { useLogin } from 'nguard/client';

export function SafeLoginForm() {
  const { login, isLoading } = useLogin();
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setMessage('');
    setError('');

    const fd = new FormData(e.currentTarget);

    try {
      const response = await login({
        email: fd.get('email'),
        password: fd.get('password'),
      });

      if (response.session) {
        setMessage('Login successful!');
      } else if (response.error) {
        setError(response.error);
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      {message && <div style={{ color: 'green' }}>{message}</div>}
      {error && <div style={{ color: 'red' }}>{error}</div>}

      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button disabled={isLoading}>
        {isLoading ? 'Loading...' : 'Login'}
      </button>
    </form>
  );
}
```

## All Hooks

| Hook | Usage |
|------|-------|
| `useSession()` | Get current session |
| `useLogin()` | Login with credentials |
| `useLogout()` | Logout user |
| `useSessionUpdate()` | Update session data |
| `useValidateSession()` | Check if session is valid |
| `useAuth()` | Alternative hook with more properties |

## Server-Side Functions

| Function | Usage |
|----------|-------|
| `auth()` | Get session in Server Components |
| `nguard.createSession()` | Create new session |
| `nguard.clearSession()` | Clear session |
| `nguard.validateSession()` | Validate token |

## Best Practices

1. **Get session in Server Components** - Better performance and SEO
2. **Handle loading states** - Show loading indicators
3. **Handle errors gracefully** - Don't crash on login errors
4. **Validate on load** - Check session when app starts
5. **Use TypeScript** - Get type safety for session data

## See Also

- [CLI Setup](./CLI-SETUP.md) - Installation
- [API Reference](./API-CLIENT.md) - All methods
- [Middleware Guide](./MIDDLEWARE.md) - Add security
- [Validation Guide](./VALIDATION.md) - Check session
