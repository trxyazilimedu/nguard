# Nguard - Quick Start (5 minutes)

Get Nguard up and running in 5 minutes!

## 1️⃣ Install

```bash
npm install nguard
```

## 2️⃣ Environment Variables

Create `.env.local`:

```env
NGUARD_SECRET=your-secret-min-32-chars-openssl-rand-base64-32
BACKEND_API_URL=http://localhost:8080/api
```

Generate secret:
```bash
openssl rand -base64 32
```

> **Note**: `BACKEND_API_URL` is your backend server address (Spring, Express, Node.js, etc.)

## 3️⃣ Server Setup (lib/auth.ts)

```typescript
import { initializeServer } from 'nguard/server';
import { headers } from 'next/headers';

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET!,
  secure: process.env.NODE_ENV === 'production',
});

// Like NextAuth - auth() function for server and client
export async function auth() {
  try {
    const headersList = await headers();
    const cookie = headersList.get('cookie');
    if (!cookie) return null;

    return await nguard.validateSession(cookie);
  } catch (error) {
    return null;
  }
}

// Helper functions
export const createSession = (user: any, data?: any) =>
  nguard.createSession(user, data);

export const clearSession = () =>
  nguard.clearSession();
```

> **Usage**: Use `auth()` function like NextAuth in server components and API routes!

## 4️⃣ Create API Routes

### Login Endpoint

```typescript
// app/api/auth/login/route.ts
import { nguard } from '@/lib/auth';

const BACKEND_API_URL = process.env.BACKEND_API_URL!;

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();

    // Step 1: Send login request to backend
    const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!backendResponse.ok) {
      throw new Error('Authentication failed');
    }

    // Step 2: Get user data from backend
    const backendData = await backendResponse.json();
    const { user } = backendData;

    // Step 3: Create session with Nguard
    const { session, setCookieHeader } = await nguard.createSession(
      user, // { id, email, name }
      { role: user.role } // Data from backend
    );

    return Response.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    console.error('Login error:', error);
    return Response.json({ error: 'Login failed' }, { status: 401 });
  }
}
```

### Logout Endpoint

```typescript
// app/api/auth/logout/route.ts
import { nguard } from '@/lib/auth';

export async function POST(request: Request) {
  return Response.json({ ok: true }, {
    headers: { 'Set-Cookie': nguard.clearSession() }
  });
}
```

### Session Endpoint

```typescript
// app/api/auth/session/route.ts
import { nguard } from '@/lib/auth';

export async function GET(request: Request) {
  try {
    const headers = Object.fromEntries(request.headers.entries());
    const session = await nguard.validateSession(headers.cookie);

    if (!session) {
      return Response.json({ session: null }, { status: 401 });
    }

    return Response.json({ session });
  } catch (error) {
    return Response.json({ session: null }, { status: 401 });
  }
}
```

## 5️⃣ Client Setup (app/layout.tsx)

### Simple Setup (Recommended)

```typescript
'use client';

import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }: any) {
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

**Default API endpoints used automatically:**
- Login: `POST /api/auth/login`
- Logout: `POST /api/auth/logout`

### With Custom Callbacks (Optional)

If you need to use different endpoints:

```typescript
'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback = async (credentials) => {
  const res = await fetch('/auth/login', { // Custom endpoint
    method: 'POST',
    body: JSON.stringify(credentials),
  });
  const data = await res.json();
  return { user: data.user, data: data.data };
};

export default function RootLayout({ children }: any) {
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

## 6️⃣ Get Session in Server Component

```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  // Like NextAuth - get session directly in server component
  const session = await auth();

  if (!session) {
    return <div>Please login first</div>;
  }

  return (
    <div>
      <h1>Welcome, {session.user.name}</h1>
      <p>Email: {session.user.email}</p>
      <p>Role: {session.data?.role}</p>
    </div>
  );
}
```

## 7️⃣ Use in Client Components

```typescript
'use client';

import { useAuth } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useAuth();

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const data = new FormData(e.currentTarget);

      try {
        // login() → client onLogin callback → POST /api/auth/login → backend auth
        await login({
          email: data.get('email'),
          password: data.get('password'),
        });
      } catch (error) {
        alert(error instanceof Error ? error.message : 'Login failed');
      }
    }}>
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}

export function Dashboard() {
  const { user, isAuthenticated, logout } = useAuth();

  if (!isAuthenticated) return <LoginForm />;

  return (
    <div>
      <h1>Welcome, {user?.name}</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## ✅ Done!

Nguard is now set up and running. Here's the flow:

1. User fills login form
2. `login()` is called
3. Client `onLogin` callback → `POST /api/auth/login`
4. Frontend API Route → **Send request to backend**
5. Backend (Spring/Express/etc.) → Authenticate user + check database
6. Backend returns user data
7. Frontend Nguard → Create JWT and set cookie
8. Session state updates
9. Component re-renders → User logged in ✅

**Key difference**: Authentication now happens on your backend. Nguard only manages JWT/session!

## 📖 Next Steps

- [CALLBACKS.md](./CALLBACKS.md) - Learn callbacks in detail
- [API-SERVER.md](./API-SERVER.md) - Server functions
- [API-CLIENT.md](./API-CLIENT.md) - Client hooks
- [EXAMPLES.md](./EXAMPLES.md) - Real-world examples
- [SESSION-UPDATE.md](./SESSION-UPDATE.md) - Updating sessions
