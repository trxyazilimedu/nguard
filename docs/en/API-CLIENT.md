# Client API Reference

Complete documentation for client-side hooks and components in Nguard.

## Overview

Nguard provides React hooks for managing authentication on the client side. Authentication functions return the API response directly without any wrapping, allowing your backend to define the response structure.

## Response Types

### login() - API Response

The `login()` function returns the response from your `/api/auth/login` endpoint directly.

**Example API Response:**

```typescript
const response = await login({ email, password });

// Response structure depends on your backend API
// Example:
{
  success: true,
  message: "Login successful",
  user: { id: 1, email: "user@example.com", name: "John" },
  data: { role: 'admin', permissions: ['read', 'write'] }
}
```

### logout() - API Response

The `logout()` function returns the response from your `/api/auth/logout` endpoint directly.

**Example API Response:**

```typescript
const response = await logout();

// Response structure depends on your backend API
// Example:
{
  success: true,
  message: "Logout successful"
}
```

### updateSession() - Local Response

The `updateSession()` function updates the local session state and returns the updated session.

**Response:**

```typescript
const response = await updateSession(updatedUser, updatedData);

// Always returns success with updated session
{
  success: true,
  message: "Session updated successfully",
  session: {
    user: SessionUser,
    expires: number,
    data?: SessionData
  }
}
```

## Error Handling

If an API call fails (network error, 4xx/5xx response), the error is thrown and should be caught:

```typescript
try {
  const response = await login({ email, password });
  // Handle response from API
} catch (error) {
  // Handle network/fetch errors
  console.error('Login failed:', error.message);
}
```

---

## Hooks

### useAuth()

Simplified authentication hook for common operations.

**Returns:**

```typescript
{
  user: SessionUser | null;           // Current user or null
  isAuthenticated: boolean;            // true if user is logged in
  isLoading: boolean;                  // true if auth is loading
  login: (credentials: any) => Promise<any>;  // Returns API response
  logout: () => Promise<any>;                 // Returns API response
}
```

**Example:**

```typescript
'use client';

import { useAuth } from 'nguard/client';

export function MyComponent() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();

  if (isLoading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return (
      <button onClick={() => login({ email: 'user@example.com', password: 'pass' })}>
        Login
      </button>
    );
  }

  return (
    <div>
      <p>Hello, {user?.name}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

### useSession()

Full session context hook. Use this when you need more control.

**Returns:**

```typescript
{
  session: Session | null;                                    // Full session object
  status: 'loading' | 'authenticated' | 'unauthenticated';   // Auth status
  login: <T = any>(credentials: T) => Promise<any>;           // Returns API response
  logout: () => Promise<any>;                                 // Returns API response
  updateSession: (user: SessionUser, data?: SessionData) => Promise<any>;  // Returns updated session
  isLoading: boolean;                                         // true if operation in progress
}
```

**Example:**

```typescript
'use client';

import { useSession } from 'nguard/client';

export function Dashboard() {
  const { session, status, login, logout, updateSession } = useSession();

  if (status === 'loading') return <div>Loading...</div>;

  if (status === 'unauthenticated') {
    return (
      <button onClick={() => login({ email: 'user@example.com', password: 'pass' })}>
        Login
      </button>
    );
  }

  return (
    <div>
      <p>User: {session?.user.name}</p>
      <p>Role: {session?.data?.role}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

### useLogin()

Login function only (simplified).

**Returns:**

```typescript
{
  login: <T = any>(credentials: T) => Promise<any>;  // Returns API response
  isLoading: boolean;
}
```

**Example:**

```typescript
'use client';

import { useLogin } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useLogin();

  async function handleSubmit(e) {
    e.preventDefault();
    try {
      const response = await login({
        email: e.target.email.value,
        password: e.target.password.value,
      });

      // Handle response from your API
      console.log('Login response:', response);
    } catch (error) {
      // Handle network/fetch errors
      alert('Login failed: ' + error.message);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button disabled={isLoading}>{isLoading ? 'Logging in...' : 'Login'}</button>
    </form>
  );
}
```

---

### useLogout()

Logout function only (simplified).

**Returns:**

```typescript
{
  logout: () => Promise<any>;  // Returns API response
  isLoading: boolean;
}
```

**Example:**

```typescript
'use client';

import { useLogout } from 'nguard/client';

export function LogoutButton() {
  const { logout, isLoading } = useLogout();

  async function handleLogout() {
    try {
      const response = await logout();

      // Handle response from your API
      console.log('Logout response:', response);
      // Optionally navigate to login page
    } catch (error) {
      // Handle network/fetch errors
      alert('Logout failed: ' + error.message);
    }
  }

  return (
    <button onClick={handleLogout} disabled={isLoading}>
      {isLoading ? 'Logging out...' : 'Logout'}
    </button>
  );
}
```

---

### useSessionUpdate()

Update session data (role, preferences, etc.).

**Returns:**

```typescript
{
  updateSession: (user: SessionUser, data?: SessionData) => Promise<UpdateSessionResponse>;
  isLoading: boolean;
}
```

**Example:**

```typescript
'use client';

import { useSessionUpdate } from 'nguard/client';
import { useSession } from 'nguard/client';

export function PreferencesForm() {
  const { updateSession, isLoading } = useSessionUpdate();
  const { session } = useSession();

  async function changeTheme(theme: string) {
    if (!session) return;

    const response = await updateSession(session.user, {
      ...session.data,
      theme,
    });

    if (response.success) {
      console.log('Theme updated');
    } else {
      alert(response.error);
    }
  }

  return (
    <div>
      <button onClick={() => changeTheme('light')} disabled={isLoading}>
        Light Theme
      </button>
      <button onClick={() => changeTheme('dark')} disabled={isLoading}>
        Dark Theme
      </button>
    </div>
  );
}
```

---

## Components

### SessionProvider

Wraps your app and provides authentication context.

**Props:**

```typescript
interface SessionProviderProps {
  children?: ReactNode;
  cookieName?: string;                    // Default: 'nguard-session'
  onLogin?: LoginCallback;                // Custom login callback (optional)
  onLogout?: LogoutCallback;              // Custom logout callback (optional)
  onInitialize?: InitializeSessionCallback; // Custom init callback (optional)
  onSessionChange?: (session: Session | null) => void; // Called when session changes
}
```

**Default Behavior:**

If you don't provide callbacks, SessionProvider uses these defaults:
- `onLogin` → POST `/api/auth/login`
- `onLogout` → POST `/api/auth/logout`

**Example:**

```typescript
// app/layout.tsx
'use client';

import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <SessionProvider>
          {children}
        </SessionProvider>
      </body>
    </html>
  );
}
```

**With Custom Callbacks:**

```typescript
'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

const customLogin: LoginCallback = async (credentials) => {
  const res = await fetch('/custom/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
  const data = await res.json();
  return {
    user: data.user,
    data: data.sessionData,
  };
};

export default function RootLayout({ children }) {
  return (
    <SessionProvider onLogin={customLogin}>
      {children}
    </SessionProvider>
  );
}
```

---

## Error Handling

### Always Check Response.success

All functions return response objects with a `success` flag. Always check this before accessing user/data:

```typescript
const response = await login(credentials);

if (response.success) {
  // Safe to use response.user and response.data
  console.log(response.user);
  console.log(response.data);
} else {
  // response.error contains the error message
  console.error(response.error);
}
```

### Handling Errors in UI

```typescript
'use client';

import { useState } from 'react';
import { useAuth } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function handleLogin(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    const formData = new FormData(e.currentTarget);
    const response = await login({
      email: formData.get('email'),
      password: formData.get('password'),
    });

    if (response.success) {
      setSuccess(true);
      // Clear form
      e.currentTarget.reset();
      // Or navigate: router.push('/dashboard')
    } else {
      setError(response.error || response.message);
    }
  }

  return (
    <form onSubmit={handleLogin}>
      {error && (
        <div style={{ color: 'red', marginBottom: '1rem' }}>
          Error: {error}
        </div>
      )}
      {success && (
        <div style={{ color: 'green', marginBottom: '1rem' }}>
          Login successful! Redirecting...
        </div>
      )}

      <input
        type="email"
        name="email"
        placeholder="Email"
        required
        disabled={isLoading}
      />
      <input
        type="password"
        name="password"
        placeholder="Password"
        required
        disabled={isLoading}
      />
      <button disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}
```

---

## Callback Types

### LoginCallback

Custom login function.

```typescript
type LoginCallback<T = any> = (credentials: T) => Promise<{
  user: SessionUser;
  data?: SessionData;
  token?: string;
}>;
```

### LogoutCallback

Custom logout function.

```typescript
type LogoutCallback = () => Promise<void>;
```

### InitializeSessionCallback

Load session on app start.

```typescript
type InitializeSessionCallback = () => Promise<Session | null>;
```

---

## TypeScript Types

Import response types for type-safe handling:

```typescript
import {
  type LoginResponse,
  type LogoutResponse,
  type UpdateSessionResponse,
} from 'nguard/client';

// Or from main export
import {
  type LoginResponse,
  type LogoutResponse,
  type UpdateSessionResponse,
} from 'nguard';
```

---

## Best Practices

### 1. Always Handle Responses

Never assume login/logout succeeds:

```typescript
// ❌ Wrong
await login(credentials);
console.log(user); // user might be null!

// ✅ Correct
const response = await login(credentials);
if (response.success) {
  console.log(response.user); // Guaranteed to exist
}
```

### 2. Show Feedback to User

Display success/error messages:

```typescript
const response = await login(credentials);
if (response.success) {
  toast.success(response.message); // "Login successful"
} else {
  toast.error(response.error);
}
```

### 3. Use Correct Hook for Your Needs

- Simple auth? → `useAuth()`
- Need more control? → `useSession()`
- Only login? → `useLogin()`
- Only logout? → `useLogout()`
- Update session? → `useSessionUpdate()`

### 4. Disable Form During Loading

Always disable form inputs while loading:

```typescript
<button disabled={isLoading}>
  {isLoading ? 'Processing...' : 'Submit'}
</button>
```

### 5. Don't Store Tokens Manually

SessionProvider handles token storage. No need to:

```typescript
// ❌ Don't do this
localStorage.setItem('token', response.token);

// ✅ Let SessionProvider handle it
const response = await login(credentials);
```

---

## Next Steps

- [QUICKSTART.md](./QUICKSTART.md) - Setup guide
- [SESSION-UPDATE.md](./SESSION-UPDATE.md) - Update session data
- [EXAMPLES.md](./EXAMPLES.md) - Real-world examples
- [BEST-PRACTICES.md](./BEST-PRACTICES.md) - Security best practices
