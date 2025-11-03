# Nguard

A Next.js 16 compatible session management library with **callback-based authentication**. Flexible, type-safe, and works with any backend.

## Features

- ✅ Server-side & Client-side Callbacks
- ✅ JWT-based Authentication
- ✅ TypeScript 100%
- ✅ Secure Cookie Management
- ✅ React Hooks (useAuth, useSession, useLogin, useLogout)
- ✅ Works with any backend (Spring, Express, Node.js, etc.)
- ✅ Next.js 16+ Support

## Installation

```bash
npm install nguard
```

## Quick Example

### 1. Server Setup (lib/auth.ts)
```typescript
import { initializeServer, type ServerLoginCallback } from 'nguard/server';

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET!,
});

// Callback: Authenticate user
const handleServerLogin: ServerLoginCallback = async (creds) => {
  const user = await db.user.findUnique({
    where: { email: creds.email }
  });
  if (!user || !verifyPassword(creds.password, user.passwordHash)) {
    throw new Error('Invalid credentials');
  }
  return { user, data: { role: user.role } };
};

nguard.onServerLogin(handleServerLogin);
```

### 2. API Routes
```typescript
// app/api/auth/login/route.ts
export async function POST(request: Request) {
  const { email, password } = await request.json();
  const { session, setCookieHeader } = await nguard.createSession(
    { id: email, email, name: 'User' },
    { role: 'user' }
  );
  return Response.json({ session }, {
    headers: { 'Set-Cookie': setCookieHeader }
  });
}
```

### 3. Client Setup (app/layout.tsx)
```typescript
'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback = async (creds) => {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(creds),
  });
  return await res.json();
};

export default function RootLayout({ children }) {
  return (
    <SessionProvider onLogin={handleLogin}>
      {children}
    </SessionProvider>
  );
}
```

### 4. Use in Components
```typescript
'use client';

import { useAuth } from 'nguard/client';

export function Dashboard() {
  const { user, isAuthenticated, login, logout } = useAuth();

  if (!isAuthenticated) {
    return (
      <form onSubmit={async (e) => {
        e.preventDefault();
        const data = new FormData(e.currentTarget);
        await login({
          email: data.get('email'),
          password: data.get('password'),
        });
      }}>
        <input type="email" name="email" placeholder="Email" required />
        <input type="password" name="password" placeholder="Password" required />
        <button>Login</button>
      </form>
    );
  }

  return (
    <div>
      <h1>Welcome, {user?.name}</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## Hooks

- `useAuth()` - Get user, isAuthenticated, login, logout
- `useSession()` - Get full session details
- `useLogin()` / `useLogout()` - Specific functions only
- `useSessionUpdate()` - Update session data

## Callbacks

**Server-side (lib/auth.ts):**
- `onServerLogin()` - User authentication
- `onServerLogout()` - Cleanup on logout
- `onValidateSession()` - Validate session
- `onJWT()` - Transform JWT payload
- `onSession()` - Transform session

**Client-side (app/layout.tsx):**
- `onLogin` - Send credentials to backend
- `onLogout` - Handle logout
- `onInitialize` - Load session on app start

## Documentation

📖 **Full Documentation Available:**

- **[Turkish (Türkçe)](./docs/tr/)** - Kapsamlı Türkçe dokümantasyon
- **[English](./docs/en/)** - Complete English documentation

### Key Docs

- [Quick Start (5 min)](./docs/tr/QUICKSTART.md)
- [API Reference](./docs/tr/API-SERVER.md) and [Callbacks](./docs/tr/CALLBACKS.md)
- [Real-world Examples](./docs/tr/EXAMPLES.md)
- [Best Practices](./docs/tr/BEST-PRACTICES.md)

## Security

- ✅ HS256 JWT signing
- ✅ Secure cookie flags (HttpOnly, Secure, SameSite)
- ✅ Cryptographic session IDs
- ✅ HTTPS support
- ✅ Server-side validation

## Environment Variables

```env
NGUARD_SECRET=your-secret-min-32-chars
# Generate: openssl rand -base64 32
```

## License

MIT

---

## Documentation Links

🇹🇷 **Türkçe Kullanıcılar:** [docs/tr/README.md](./docs/tr/README.md)

🇬🇧 **English Users:** [docs/en/README.md](./docs/en/README.md)
