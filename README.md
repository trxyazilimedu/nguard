<div align="center">
  <img src="./docs/tr/logo.png" alt="Nguard Logo" width="200" />
</div>

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

## Installation & Setup

### Automatic Setup (Recommended)

```bash
# 1. Install package
npm install nguard

# 2. Run interactive setup wizard
npx nguard-setup
```

The wizard will automatically create:
- ✅ `lib/auth.ts` - Server authentication utilities
- ✅ API routes (`/api/auth/login`, `/api/auth/logout`, etc.)
- ✅ `proxy.ts` - Next.js 16 middleware configuration
- ✅ `.env.local` - Environment variables template
- ✅ TypeScript path aliases

> 📖 For detailed setup wizard guide, see [CLI-SETUP.md](./docs/en/CLI-SETUP.md)

## Quick Example (After Setup)

### 1. Configure Environment
```bash
cp .env.local.example .env.local
# Edit with your BACKEND_API_URL and generated NGUARD_SECRET
```

### 2. Client Setup (app/layout.tsx)
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

### 3. Server Component
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();

  if (!session) {
    return <div>Please log in</div>;
  }

  return <div>Welcome {session.email}</div>;
}
```

### 4. Client Component
```typescript
'use client';

import { useSession, useLogin, useLogout } from 'nguard/client';

export function LoginForm() {
  const { session } = useSession();
  const { login, isLoading } = useLogin();
  const { logout } = useLogout();

  if (session) {
    return (
      <div>
        <p>Logged in as {session.email}</p>
        <button onClick={logout}>Logout</button>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const response = await login({
      email: formData.get('email'),
      password: formData.get('password'),
    });
    if (response.session) {
      // Success
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

### 🚀 Quick Start
- **[CLI Setup Wizard](./docs/en/CLI-SETUP.md)** - Interactive setup guide (2 minutes)

### 📚 API Reference & Usage
- **[API Reference](./docs/en/API-CLIENT.md)** - Hooks, methods, and response types
- **[Middleware Guide](./docs/en/MIDDLEWARE.md)** - Built-in middleware system
- **[Session Validation](./docs/en/VALIDATION.md)** - Validation patterns and examples

### 🌐 Languages
- **[Türkçe Dokümantasyon](./docs/tr/)** - Turkish documentation
- **[English Documentation](./docs/en/)** - English documentation

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
