# CLI Setup Guide

The interactive CLI setup wizard automatically configures Nguard in your Next.js 16+ project.

## Installation

```bash
npm install nguard
npx nguard-setup
```

## What the Wizard Does

The CLI asks a few questions and creates:

1. **lib/auth.ts** - Server-side authentication utilities
2. **API routes** - `/api/auth/login`, `/api/auth/logout`, `/api/auth/validate`, `/api/auth/refresh`
3. **proxy.ts** - Next.js 16 middleware configuration
4. **.env.local.example** - Environment variables template
5. **tsconfig.json updates** - Path aliases (`@/*`)

## Interactive Setup Flow

### Step 1: Confirmation

The wizard displays what it will create and asks for your approval:

```
⚠️ This wizard will create/modify:
- lib/auth.ts
- app/api/auth/ routes
- proxy.ts
- .env.local.example

Continue? (y/n):
Accept responsibility? (y/n):
```

### Step 2: Project Configuration

```
TypeScript project? (y/n):
App directory (default: app):
Cookie name (default: nguard-session):
Environment (default: development):
```

### Step 3: Select Routes

Choose which authentication endpoints to create:

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

Edit `.env.local`:

```env
NGUARD_SECRET=your-32-character-secret
BACKEND_API_URL=http://localhost:8080/api
NODE_ENV=development
```

Generate a secret:
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

### 3. Start Using

**Server Component:**
```typescript
import { auth } from '@/lib/auth';

export default async function Page() {
  const session = await auth();
  return <div>Hello {session?.email}</div>;
}
```

**Client Component:**
```typescript
'use client';

import { useSession, useLogin } from 'nguard/client';

export function MyComponent() {
  const { session } = useSession();
  const { login } = useLogin();

  return <div>{session?.email}</div>;
}
```

## Customizing Routes

Edit the generated routes to add your backend logic:

```typescript
// app/api/auth/login/route.ts
import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

const BACKEND_API_URL = process.env.BACKEND_API_URL || '';

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    // Call your backend
    const res = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) throw new Error('Auth failed');

    const data = await res.json();

    // Create session with backend data
    const { session, setCookieHeader } = await nguard.createSession({
      ...data,
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

## Adding Middleware

Edit `proxy.ts` to add security middleware:

```typescript
import { compose, requireAuth, logger } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger({ onLog: (data) => console.log(data) }),
    // requireAuth, // Uncomment to protect routes
  );

  const response = await middleware(request, null);
  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| TypeScript errors | Check `tsconfig.json` has `@/*` path alias |
| Routes not found | Verify files in `app/api/auth/[route]/route.ts` |
| Session not persisting | Check `.env.local` has `NGUARD_SECRET` set |
| Import errors | Ensure `@/*` alias exists, restart dev server |

## File Structure

```
your-project/
├── app/
│   ├── api/auth/
│   │   ├── login/route.ts
│   │   ├── logout/route.ts
│   │   ├── validate/route.ts
│   │   └── refresh/route.ts
│   └── layout.tsx (SessionProvider)
├── lib/
│   └── auth.ts
├── proxy.ts
├── .env.local
├── .env.local.example
└── tsconfig.json (updated)
```

## See Also

- [Quick Start](./QUICKSTART.md) - Learn hooks
- [API Reference](./API-CLIENT.md) - All methods
- [Middleware Guide](./MIDDLEWARE.md) - Middleware patterns
- [Validation Guide](./VALIDATION.md) - Check session validity
