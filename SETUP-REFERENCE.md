# Nguard Setup Reference

Complete checklist for integrating Nguard into your Next.js 16+ project.

## Automatic Setup (Recommended)

```bash
# Run the interactive CLI setup
npm run setup
```

The CLI will:
- ✅ Ask for TypeScript/JavaScript preference
- ✅ Create lib/auth.ts with auth() function
- ✅ Generate API routes (login, logout, validate, refresh)
- ✅ Create proxy.ts configuration (Next.js 16)
- ✅ Generate .env.local.example template
- ✅ Update tsconfig.json with path aliases
- ✅ Request confirmation before making changes

## Manual Setup (If Needed)

### 1. Install Dependencies

```bash
npm install nguard jsonwebtoken
npm install -D @types/jsonwebtoken
```

### 2. Create Environment Variables

Copy template and configure:
```bash
cp .env.local.example .env.local
```

Generate JWT secret:
```bash
openssl rand -base64 32
```

### 3. Update app/layout.tsx

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

### 4. Create Authentication

**Server-side (Server Components):**
```typescript
import { auth } from '@/lib/auth';

export default async function Page() {
  const session = await auth();
  return <div>{session?.email}</div>;
}
```

**Client-side (Client Components):**
```typescript
'use client';

import { useSession, useLogin } from 'nguard/client';

export default function Component() {
  const { session } = useSession();
  const { login } = useLogin();

  return (
    <button onClick={() => login({ email: 'x@y.com', password: 'pass' })}>
      Login
    </button>
  );
}
```

## File Structure After Setup

```
project/
├── app/
│   ├── api/
│   │   └── auth/
│   │       ├── login/
│   │       │   └── route.ts (POST)
│   │       ├── logout/
│   │       │   └── route.ts (POST)
│   │       ├── validate/
│   │       │   └── route.ts (GET/POST/HEAD)
│   │       └── refresh/
│   │           └── route.ts (POST)
│   ├── layout.tsx (SessionProvider)
│   └── page.tsx (Your components)
├── lib/
│   └── auth.ts (Server auth utilities)
├── proxy.ts (Middleware - Next.js 16)
├── .env.local (Environment variables)
├── .env.local.example (Template)
├── tsconfig.json (Updated with @/*)
└── package.json
```

## Key Features

### Server-Side Auth
```typescript
import { auth } from '@/lib/auth';

const session = await auth();
// Returns: { id, email, role, ... } or null
```

### Client-Side Hooks
```typescript
const { session, loading } = useSession();
const { login, isLoading } = useLogin();
const { logout } = useLogout();
const { updateSession } = useSessionUpdate();
const { validate, isValid } = useValidateSession();
```

### Session Validation
```typescript
// Check if session is valid
const response = await fetch('/api/auth/validate');
const { valid, session, expiresIn } = await response.json();
```

### Middleware
```typescript
import { compose, requireAuth, logger } from 'nguard';

export async function proxy(request) {
  const middleware = compose(
    logger(),
    requireAuth,
  );
  return await middleware(request, session) || NextResponse.next();
}
```

## Next Steps

1. **Read Documentation**
   - [CLI Setup Guide](./docs/en/CLI-SETUP.md)
   - [API Reference](./docs/en/API-CLIENT.md)
   - [Middleware Guide](./docs/en/MIDDLEWARE.md)
   - [Validation Guide](./docs/en/VALIDATION.md)

2. **Configure Backend**
   - Ensure backend has `/auth/login` endpoint
   - Backend should return session object with `expires` field
   - Set `BACKEND_API_URL` in .env.local

3. **Customize**
   - Edit API routes in `app/api/auth/*/route.ts`
   - Add middleware in `proxy.ts`
   - Customize cookie settings in `.env.local`

4. **Test**
   ```bash
   npm run dev
   # Visit http://localhost:3000
   ```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| TypeScript errors | Run `npm run build` and check path aliases in tsconfig.json |
| Session not persisting | Verify NGUARD_SECRET is set and backend is responding |
| Routes not found | Check files are in `app/api/auth/[route]/route.ts` |
| Import errors | Ensure tsconfig.json has `@/*` path alias |

## CLI Usage

```bash
# Run setup
npm run setup

# Options during setup:
# 1. TypeScript project? (y/n)
# 2. App directory? (default: app)
# 3. Cookie name? (default: nguard-session)
# 4. Environment? (default: development)
# 5. Which routes? (login, logout, validate, refresh)
```

## Documentation

- **[CLI-SETUP.md](./docs/en/CLI-SETUP.md)** - Interactive setup guide
- **[QUICKSTART.md](./docs/en/QUICKSTART.md)** - Quick start guide
- **[API-CLIENT.md](./docs/en/API-CLIENT.md)** - Client API reference
- **[MIDDLEWARE.md](./docs/en/MIDDLEWARE.md)** - Middleware system guide
- **[VALIDATION.md](./docs/en/VALIDATION.md)** - Session validation guide

## Turkish Documentation

- **[CLI-SETUP.md](./docs/tr/CLI-SETUP.md)** - CLI Kurulum Rehberi
- **[QUICKSTART.md](./docs/tr/QUICKSTART.md)** - Hızlı Başlangıç
- **[API-CLIENT.md](./docs/tr/API-CLIENT.md)** - İstemci API Referansı
- **[MIDDLEWARE.md](./docs/tr/MIDDLEWARE.md)** - Ara Yazılım Rehberi
- **[VALIDATION.md](./docs/tr/VALIDATION.md)** - Doğrulama Rehberi

## Support

- GitHub: https://github.com/trxyazilimedu/nguard
- Issues: https://github.com/trxyazilimedu/nguard/issues
