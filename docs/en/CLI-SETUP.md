# Nguard CLI Setup Guide

The Nguard CLI Setup Wizard automates the integration of Nguard authentication into your Next.js 16+ project with a simple interactive wizard.

## Quick Start

```bash
# Install Nguard
npm install nguard

# Run the setup wizard
npx nguard-setup
```

That's it! The wizard will guide you through the setup and create all necessary files.

## What Gets Generated

### 1. **lib/auth.ts** (or lib/auth.js)

Server-side authentication utilities with:
- `nguard` - Initialized server instance
- `auth()` - Get current session in Server Components
- Helper functions: `createSession()`, `clearSession()`, `updateSession()`, `validateSession()`

### 2. **API Routes** - `app/api/auth/[route]/route.ts`

Automatically created endpoints (you choose which ones):

- **POST /api/auth/login** - Create session
- **POST /api/auth/logout** - Clear session
- **GET /api/auth/validate** - Check session validity
- **POST /api/auth/refresh** - Extend session

### 3. **proxy.ts** (Next.js 16+)

Replaces `middleware.ts`. Set up your middleware:
- Authentication requirements
- Role-based access control
- Request logging
- CORS headers
- Session validation

### 4. **.env.local.example**

Environment template:
```env
NGUARD_SECRET=your-32-char-secret
BACKEND_API_URL=http://localhost:8080/api
NODE_ENV=development
```

### 5. **tsconfig.json** Updates

Path aliases for cleaner imports:
```typescript
// Before: import { auth } from '../../../lib/auth'
// After:  import { auth } from '@/lib/auth'
```

## Interactive Setup Process

### Step 1: Confirmation

```
⚠️ DISCLAIMER:
This wizard will create/modify files in your project:
- lib/auth.ts
- app/api/auth/ routes
- proxy.ts
- .env.local.example

Do you want to continue? (y/n):
Do you take full responsibility? (y/n):
```

### Step 2: Project Configuration

```
Is this a TypeScript project? (y/n):
App directory path (default: app):
Cookie name (default: nguard-session):
Environment (default: development):
```

### Step 3: Select Auth Routes

Choose which routes to create:
```
Create /api/auth/login? (recommended) (y/n):
Create /api/auth/logout? (recommended) (y/n):
Create /api/auth/validate? (recommended) (y/n):
Create /api/auth/refresh? (y/n):
```

## After Setup

### 1. Configure Environment

```bash
cp .env.local.example .env.local
```

Generate a JWT secret:
```bash
openssl rand -base64 32
```

### 2. Add SessionProvider

In `app/layout.tsx`:

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

### 3. Use in Your Components

**Server Component:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();
  if (!session) return <div>Not logged in</div>;

  return <div>Welcome {session.email}</div>;
}
```

**Client Component:**
```typescript
'use client';

import { useSession, useLogin, useLogout } from 'nguard/client';

export default function Profile() {
  const { session } = useSession();
  const { login, isLoading } = useLogin();
  const { logout } = useLogout();

  if (!session) {
    return (
      <form onSubmit={async (e) => {
        e.preventDefault();
        await login({
          email: 'user@example.com',
          password: 'password',
        });
      }}>
        <input type="email" placeholder="Email" required />
        <input type="password" placeholder="Password" required />
        <button disabled={isLoading}>Login</button>
      </form>
    );
  }

  return (
    <div>
      <p>Logged in as {session.email}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### 4. Customize API Routes

Edit `app/api/auth/login/route.ts` to add your backend logic:

```typescript
// app/api/auth/login/route.ts
import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

const BACKEND_API_URL = process.env.BACKEND_API_URL || '';

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    // Call your backend
    const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!backendResponse.ok) {
      throw new Error('Authentication failed');
    }

    const backendData = await backendResponse.json();

    // Create session with backend data
    const { session, setCookieHeader } = await nguard.createSession({
      ...backendData,
      expires: Date.now() + 24 * 60 * 60 * 1000,
    });

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
```

### 5. Add Middleware

Edit `proxy.ts` to add security middleware:

```typescript
import { compose, requireAuth, logger } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function proxy(request: NextRequest) {
  const session = null; // Extract from cookies if needed

  const middleware = compose(
    logger({
      onLog: (data) => console.log('[Request]', data.method, data.path),
    }),
    // Add requireAuth for protected routes:
    // requireAuth,
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico|public).*)'],
};
```

## Customization Options

### Change Cookie Name

```bash
# Edit .env.local
NGUARD_COOKIE_NAME=my-session
```

### Set TypeScript Path Aliases

Already done by CLI, but manually add to `tsconfig.json` if needed:

```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./*"]
    }
  }
}
```

### Custom Session Data

The session accepts any data structure:

```typescript
await nguard.createSession({
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  permissions: ['read', 'write'],
  customField: 'any value',
  expires: Date.now() + 24 * 60 * 60 * 1000,
});
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| TypeScript errors | Verify `tsconfig.json` has `@/*` path alias, run `npm run build` |
| Session not persisting | Check `.env.local` has `NGUARD_SECRET`, verify backend is running |
| Routes not found | Verify files in `app/api/auth/[route]/route.ts` |
| Import errors | Ensure `@/*` path alias in `tsconfig.json`, restart dev server |

## File Structure After Setup

```
your-project/
├── app/
│   ├── api/auth/
│   │   ├── login/route.ts
│   │   ├── logout/route.ts
│   │   ├── validate/route.ts
│   │   └── refresh/route.ts
│   ├── layout.tsx (with SessionProvider)
│   └── page.tsx
├── lib/
│   └── auth.ts
├── proxy.ts
├── .env.local
├── .env.local.example
├── tsconfig.json (updated)
└── package.json
```

## See Also

- [API Reference](./API-CLIENT.md) - All hooks and methods
- [Middleware Guide](./MIDDLEWARE.md) - Middleware system
- [Session Validation](./VALIDATION.md) - Validation patterns
- [SETUP-REFERENCE](../SETUP-REFERENCE.md) - Quick reference
