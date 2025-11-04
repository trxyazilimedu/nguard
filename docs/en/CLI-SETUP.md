# Nguard CLI Setup Guide

The Nguard CLI Setup Wizard automates the integration of Nguard authentication into your Next.js 16+ project. It generates all necessary configuration files, API routes, and TypeScript types.

## Quick Start

```bash
npm run setup
```

That's it! The interactive wizard will guide you through the setup process.

## What Gets Generated

The CLI creates the following files in your Next.js project:

### 1. **lib/auth.ts** (or lib/auth.js for JavaScript projects)

Server-side authentication utilities including:
- `nguard` - Initialized server instance
- `auth()` - Async function to get current session in Server Components
- Helper functions: `createSession()`, `clearSession()`, `updateSession()`, `validateSession()`

**Example:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();

  if (!session) {
    return <div>Not authenticated</div>;
  }

  return <div>Welcome {session.email}</div>;
}
```

### 2. **app/api/auth/[route]/route.ts** - API Routes

The wizard creates one or more of these authentication endpoints:

#### POST /api/auth/login
Authenticates user and creates session:
```json
Request:
{
  "email": "user@example.com",
  "password": "password123"
}

Response:
{
  "session": {
    "id": "user-123",
    "email": "user@example.com",
    "role": "admin"
  }
}
```

#### POST /api/auth/logout
Clears session and removes authentication cookie:
```json
Response:
{ "ok": true }
```

#### GET /api/auth/validate
Validates current session from cookies:
```json
Response:
{
  "valid": true,
  "session": { ... },
  "expiresIn": 3600000
}
```

#### POST /api/auth/refresh
Refreshes session expiration:
```json
Response:
{ "ok": true }
```

### 3. **proxy.ts** (Next.js 16+)

Replaces the old `middleware.ts` file. This is where you can add middleware like:
- Authentication requirements
- Role-based access control
- Request logging
- CORS headers
- Session validation

The generated proxy.ts includes:
- Session extraction from cookies
- Basic middleware composition setup
- Placeholder for custom middleware

**Note:** Next.js 16 uses `proxy.ts` instead of `middleware.ts` to make the network boundary explicit.

### 4. **.env.local.example**

Environment variables template:

```env
# JWT Secret (minimum 32 characters)
# Generate with: openssl rand -base64 32
NGUARD_SECRET=your-secret-min-32-chars-here

# Backend API URL
BACKEND_API_URL=http://localhost:8080/api

# Environment
NODE_ENV=development

# Session cookie configuration (optional)
# NGUARD_COOKIE_NAME=nguard-session
# NGUARD_COOKIE_SECURE=true
# NGUARD_COOKIE_SAME_SITE=Strict
```

### 5. **tsconfig.json** (Path Alias)

For TypeScript projects, the wizard updates your tsconfig.json to add path alias:

```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./*"]
    }
  }
}
```

This allows cleaner imports:
```typescript
// Before
import { auth } from '../../../lib/auth';

// After
import { auth } from '@/lib/auth';
```

## Interactive Setup Process

### Step 1: Welcome & Disclaimer

The wizard displays a disclaimer about file modifications:
- Creates `lib/auth.ts` or `lib/auth.js`
- Creates API routes under `app/api/auth/`
- Creates or updates `proxy.ts`
- Adds environment variables template

### Step 2: Responsibility Confirmation

You must confirm:
1. "Do you want to continue? This action cannot be undone." → **y**
2. "Do you take full responsibility for these changes and understand the risks?" → **y**

### Step 3: Project Configuration

The wizard asks:

```
📋 PROJECT CONFIGURATION

Project Root: /path/to/your/project

Is this a TypeScript project? (y/n):
```

**TypeScript vs JavaScript:**
- **y** - Generates `.ts` files with full type support
- **n** - Generates `.js` files with JSDoc comments

### Step 4: Customize Paths

```
App directory path (default: app):
```

Press Enter to use default or specify custom path (e.g., `src/app`).

### Step 5: Session Configuration

```
Cookie name for session (default: nguard-session):
```

Customize the session cookie name or press Enter for default.

### Step 6: Environment Selection

```
Environment (development/production, default: development):
```

Affects the `NODE_ENV` in `.env.local.example`.

### Step 7: Select Auth Routes

Choose which routes to generate:

```
Create /api/auth/login? (recommended) (y/n):
Create /api/auth/logout? (recommended) (y/n):
Create /api/auth/validate? (recommended) (y/n):
Create /api/auth/refresh? (y/n):
```

- **login/logout/validate** - Recommended for most projects
- **refresh** - Optional, for session extension

## After Setup

### 1. Set Environment Variables

```bash
cp .env.local.example .env.local
```

Edit `.env.local` with your configuration:
- Generate JWT secret: `openssl rand -base64 32`
- Set your backend API URL
- Configure cookie settings

### 2. Install Nguard Package

```bash
npm install nguard
```

### 3. Update Your Layout

In `app/layout.tsx`:

```typescript
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

### 4. Start Using Authentication

**In Server Components:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();
  if (!session) return <div>Not authenticated</div>;

  return <div>Welcome {session.email}</div>;
}
```

**In Client Components:**
```typescript
'use client';

import { useSession, useLogin } from 'nguard/client';

export default function LoginForm() {
  const { session, loading } = useSession();
  const { login, isLoading } = useLogin();

  const handleLogin = async (credentials) => {
    const response = await login(credentials);
    if (response.session) {
      // Success
    }
  };

  return (
    // Your login form JSX
  );
}
```

### 5. Test Your Setup

```bash
npm run dev
```

Visit `http://localhost:3000` and test the authentication flow.

## Customization After Setup

### Modify API Routes

Edit the generated route files to add custom logic:

```typescript
// app/api/auth/login/route.ts
export async function POST(request: NextRequest) {
  const { email, password } = await request.json();

  // Add your custom authentication logic

  const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  // Handle response
}
```

### Add Middleware

Edit `proxy.ts` to add authentication middleware:

```typescript
import { compose, requireAuth, logger } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger({
      onLog: (data) => console.log(data),
    }),
    requireAuth, // Require authentication
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### Change Cookie Settings

Update `.env.local`:

```env
NGUARD_COOKIE_NAME=my-custom-session
NGUARD_COOKIE_SECURE=true        # HTTPS only
NGUARD_COOKIE_SAME_SITE=Strict  # CSRF protection
```

## Troubleshooting

### TypeScript Errors After Setup

If you get TypeScript errors:

1. Ensure `tsconfig.json` has the `@/*` path alias
2. Run: `npm run build` to verify compilation
3. Check that `dist/` has been generated

### Session Not Persisting

1. Verify `.env.local` has `NGUARD_SECRET` set
2. Check that backend is responding to `/auth/login`
3. Inspect cookies in browser DevTools

### Routes Not Working

1. Verify files are in correct location: `app/api/auth/[route]/route.ts`
2. Check that `Next.js 16+` is installed
3. Restart dev server: `npm run dev`

### Import Errors

If you get "Cannot find module '@/lib/auth'":

1. Verify `lib/auth.ts` was created
2. Check `tsconfig.json` has `@/*` path alias
3. Ensure you're not in the build folder when importing

## CLI Options

### Help

```bash
npm run setup -- --help
```

### Skip Interactive Mode (Future)

Currently, the setup always runs in interactive mode. Non-interactive mode may be added in future versions.

## File Structure After Setup

```
your-project/
├── app/
│   ├── api/
│   │   └── auth/
│   │       ├── login/
│   │       │   └── route.ts
│   │       ├── logout/
│   │       │   └── route.ts
│   │       ├── validate/
│   │       │   └── route.ts
│   │       └── refresh/
│   │           └── route.ts
│   └── layout.tsx
├── lib/
│   └── auth.ts              ← Server auth utilities
├── proxy.ts                  ← Middleware (Next.js 16)
├── .env.local               ← Environment variables
├── .env.local.example       ← Template (generated)
├── tsconfig.json            ← Updated with @/*
└── package.json
```

## Next Steps

1. **[Middleware Documentation](./MIDDLEWARE.md)** - Learn about middleware system
2. **[Validation Documentation](./VALIDATION.md)** - Implement session validation
3. **[API Reference](./API-SERVER.md)** - Full API documentation
4. **[Examples](../examples/)** - Real-world implementation examples

## Support

For issues or questions:
- GitHub Issues: https://github.com/trxyazilimedu/nguard/issues
- Documentation: https://github.com/trxyazilimedu/nguard
