<h1 align="center">
  <img alt="Nguard" src="./docs/tr/logo.png" width="220" style="max-width: 100%;" />
</h1>

<p align="center">
  <strong>Next.js 16+ Session Management Library</strong><br/>
  Zero-config authentication • JWT-based sessions • Works with any backend
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#hooks">Hooks</a> •
  <a href="#docs">Documentation</a>
</p>

---

## Installation

```bash
npm install nguard
npx nguard-setup
```

That's it! The wizard will automatically create:
- ✅ `lib/auth.ts` - Server authentication utilities
- ✅ API routes - `/api/auth/login`, `/api/auth/logout`, `/api/auth/validate`
- ✅ `proxy.ts` - Next.js 16 middleware
- ✅ `.env.local.example` - Configuration template

## Quick Start

### 1. Wrap your app with SessionProvider

```typescript
// app/layout.tsx
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

### 2. Get session in Server Components

```typescript
// app/dashboard/page.tsx
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();

  if (!session) {
    return <div>Please log in</div>;
  }

  return <div>Welcome, {session.email}</div>;
}
```

### 3. Use hooks in Client Components

```typescript
// app/components/login.tsx
'use client';

import { useLogin } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useLogin();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);

    const response = await login({
      email: formData.get('email'),
      password: formData.get('password'),
    });

    if (response.session) {
      console.log('Logged in!');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}
```

## Hooks

### useSession()
Get the current session

```typescript
const { session, loading } = useSession();
```

### useLogin()
Login with credentials

```typescript
const { login, isLoading } = useLogin();
const response = await login({ email, password });
```

### useLogout()
Logout the user

```typescript
const { logout, isLoading } = useLogout();
await logout();
```

### useSessionUpdate()
Update session data

```typescript
const { updateSession, isLoading } = useSessionUpdate();
await updateSession(newSessionData);
```

### useValidateSession()
Check if session is valid

```typescript
const { validate, isValid, validationResult } = useValidateSession();
await validate();
```

## Server-Side

### auth()
Get session in Server Components

```typescript
import { auth } from '@/lib/auth';

const session = await auth();
```

### createSession()
Create a new session

```typescript
import { nguard } from '@/lib/auth';

const { session, setCookieHeader } = await nguard.createSession({
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  expires: Date.now() + 24 * 60 * 60 * 1000,
});
```

### clearSession()
Clear the session

```typescript
const cookieHeader = nguard.clearSession();
```

### validateSession()
Validate a session token

```typescript
const session = await nguard.validateSession(cookieString);
```

## Features

- ✅ **Zero-config** - SessionProvider needs no callbacks
- ✅ **TypeScript** - 100% type-safe
- ✅ **JWT Sessions** - Secure, stateless authentication
- ✅ **Server Components** - Works with async/await
- ✅ **Client Hooks** - useSession, useLogin, useLogout
- ✅ **Middleware** - Built-in role-based access control
- ✅ **Session Validation** - Check session validity anytime
- ✅ **Any Backend** - Works with Spring, Express, Django, etc.
- ✅ **Next.js 16+** - Compatible with latest Next.js

## Architecture

```
Next.js App
    ↓
SessionProvider (manages session state)
    ↓
useLogin/useLogout/useSession hooks
    ↓
API Routes (/api/auth/login, /api/auth/logout, etc)
    ↓
Your Backend (Spring, Express, Django, etc)
    ↓
JWT Token ← Session Data
    ↓
HTTP-only Cookie
```

## Docs

- 📖 **[CLI Setup Guide](./docs/en/CLI-SETUP.md)** - Interactive setup wizard
- 🚀 **[Quick Start](./docs/en/QUICKSTART.md)** - Learn hooks and usage
- 📚 **[API Reference](./docs/en/API-CLIENT.md)** - All methods and hooks
- ⚙️ **[Middleware Guide](./docs/en/MIDDLEWARE.md)** - Role-based access control
- ✔️ **[Validation Guide](./docs/en/VALIDATION.md)** - Check session validity

### Turkish Docs
- 📖 **[CLI Kurulum Rehberi](./docs/tr/CLI-SETUP.md)**
- 🚀 **[Hızlı Başlangıç](./docs/tr/QUICKSTART.md)**

## Example Response

Your backend determines the response structure:

```typescript
// Login endpoint returns
{
  session: {
    id: 'user-123',
    email: 'user@example.com',
    role: 'admin',
    permissions: ['read', 'write']
  }
}
```

## Environment Variables

```env
NGUARD_SECRET=your-32-character-secret
BACKEND_API_URL=http://localhost:8080/api
NODE_ENV=development
```

Generate a secret:
```bash
openssl rand -base64 32
```

## Security

- ✅ HTTP-only cookies
- ✅ CSRF protection
- ✅ Secure cookie flags
- ✅ JWT validation
- ✅ Session expiration

## License

MIT

---

<p align="center">
  <strong>Ready to get started?</strong><br/>
  <code>npm install nguard && npx nguard-setup</code>
</p>
