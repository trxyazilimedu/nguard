# Middleware System

Nguard provides a flexible, composable middleware system for Next.js that works seamlessly with `next-intl` and other middleware libraries.

## Overview

The middleware system is designed with these principles:

- **Flexible**: Use individual middleware or compose them
- **Composable**: Chain middleware in any order
- **Compatible**: Works with next-intl, i18n, and other middleware
- **Typed**: Full TypeScript support
- **Non-intrusive**: Doesn't interfere with other middleware

## Basic Usage

### Simple Authentication Middleware

```typescript
// middleware.ts
import { requireAuth } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function middleware(request: NextRequest) {
  const session = null; // Get from cookies or your session store
  const authMiddleware = requireAuth();

  const response = authMiddleware(request, session);

  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)',
};
```

### Role-Based Access Control

```typescript
import { requireRole } from 'nguard';

export async function middleware(request: NextRequest) {
  const session = getSessionFromCookie(request);

  if (request.nextUrl.pathname.startsWith('/admin')) {
    const adminMiddleware = requireRole('admin');
    const response = adminMiddleware(request, session);

    if (response) return response;
  }

  return NextResponse.next();
}
```

## Available Middleware

### requireAuth()

Requires valid session to access the route.

```typescript
const middleware = requireAuth();
// Returns: Redirects to /login if no session
```

### requireRole(role)

Requires user to have specific role.

```typescript
const middleware = requireRole('admin');
// or multiple roles
const middleware = requireRole(['admin', 'moderator']);
// Returns: 403 if user doesn't have role
```

### requirePermission(permission)

Requires user to have specific permission(s).

```typescript
const middleware = requirePermission('users:read');
// or multiple permissions
const middleware = requirePermission(['posts:create', 'posts:edit']);
// Returns: 403 if user doesn't have permission
```

**Note**: Permissions must be stored in session as:
```typescript
{
  permissions: ['users:read', 'posts:create'],
  role: 'editor'
}
```

### rateLimit(config)

Rate limiting per user or IP.

```typescript
import { rateLimit } from 'nguard';

const middleware = rateLimit({
  maxRequests: 100,
  windowMs: 60 * 1000, // 1 minute
});
// Returns: 429 (Too Many Requests) when exceeded
```

### logger(config)

Log requests with optional custom handler.

```typescript
import { logger } from 'nguard';

const middleware = logger({
  onLog: (data) => {
    console.log(`${data.method} ${data.pathname}`);
    // Send to analytics, sentry, etc.
  },
});
```

### cors(config)

Handle CORS headers.

```typescript
import { cors } from 'nguard';

const middleware = cors({
  allowedOrigins: ['http://localhost:3000', 'https://example.com'],
  allowedMethods: ['GET', 'POST'],
  credentials: true,
  maxAge: 3600,
});
```

### injectHeaders(headers)

Inject custom headers into response.

```typescript
import { injectHeaders } from 'nguard';

const middleware = injectHeaders({
  'X-Custom-Header': 'value',
  'X-Security-Policy': 'strict',
});
```

## Composing Middleware

### compose()

Combine multiple middleware into one.

```typescript
import { compose, requireAuth, logger, rateLimit } from 'nguard';

export async function middleware(request: NextRequest) {
  const session = getSession(request);

  const middleware = compose(
    logger(),
    rateLimit({ maxRequests: 100, windowMs: 60000 }),
    requireAuth()
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### when()

Conditionally execute middleware.

```typescript
import { when, requireAuth } from 'nguard';

const middleware = when(
  (req) => req.nextUrl.pathname.startsWith('/api'),
  requireAuth()
);
```

### onPath()

Execute middleware only for specific paths.

```typescript
import { onPath, requireRole } from 'nguard';

const middleware = onPath(
  /^\/admin/,  // RegExp
  requireRole('admin')
);

// or with string
const middleware = onPath('/dashboard', requireAuth());

// or with function
const middleware = onPath(
  (pathname) => pathname.startsWith('/api/protected'),
  requireAuth()
);
```

## Integration with next-intl

Nguard middleware is designed to work seamlessly with `next-intl`. Here's the proper setup:

```typescript
// middleware.ts
import { createIntlMiddleware } from 'next-intl/middleware';
import { compose, requireAuth, requireRole } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';
import { Session } from 'nguard';

const locales = ['en', 'tr', 'es'];
const intlMiddleware = createIntlMiddleware({
  locales,
  defaultLocale: 'en',
});

export async function middleware(request: NextRequest) {
  // Step 1: Apply i18n first
  const intlResponse = intlMiddleware(request);

  // Step 2: Get session
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;
  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {}
  }

  // Step 3: Apply Nguard middleware
  const authMiddleware = compose(
    requireAuth(),
    requireRole('user')
  );

  const authResponse = await authMiddleware(request, session);

  if (authResponse) {
    // Merge headers from both responses
    authResponse.headers.forEach((value, key) => {
      if (!intlResponse.headers.has(key)) {
        intlResponse.headers.set(key, value);
      }
    });
    return authResponse;
  }

  return intlResponse;
}

export const config = {
  matcher: ['/((?!api|_next|favicon.ico).*),'],
};
```

## Error Handling

### withErrorHandling()

Wrap middleware with error handling.

```typescript
import { withErrorHandling, requireAuth } from 'nguard';

const safeAuth = withErrorHandling(
  requireAuth(),
  (error) => {
    console.error('Auth error:', error);
    return NextResponse.json(
      { error: 'Authentication failed' },
      { status: 500 }
    );
  }
);
```

## Custom Middleware

Create your own middleware:

```typescript
import { NguardMiddleware } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';
import { Session } from 'nguard';

const customMiddleware: NguardMiddleware = (request, session) => {
  // Your logic here

  if (someCondition) {
    return NextResponse.json(
      { error: 'Forbidden' },
      { status: 403 }
    );
  }

  // Return nothing to continue
};

export async function middleware(request: NextRequest) {
  const session = getSession(request);
  const response = customMiddleware(request, session);

  return response || NextResponse.next();
}
```

## Session Structure

Your session object can have any structure. Here are common patterns:

```typescript
// Basic session
{
  id: 'user-123',
  email: 'user@example.com',
  name: 'John Doe',
  expires: 1234567890000
}

// With role
{
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  expires: 1234567890000
}

// With permissions
{
  id: 'user-123',
  email: 'user@example.com',
  permissions: ['users:read', 'posts:create'],
  expires: 1234567890000
}

// Complex structure
{
  id: 'user-123',
  email: 'user@example.com',
  profile: {
    name: 'John Doe',
    avatar: 'https://...',
  },
  role: 'admin',
  permissions: ['users:read', 'posts:create'],
  settings: {
    theme: 'dark',
    language: 'en',
  },
  expires: 1234567890000
}
```

## Best Practices

1. **Apply middleware in order**: Apply i18n first, then authentication
2. **Get session early**: Extract session from cookies at the start
3. **Use compose for clarity**: Group related middleware
4. **Handle errors**: Use `withErrorHandling()` for important middleware
5. **Test integration**: Test with other middleware libraries
6. **Performance**: Cache session parsing if needed

## Performance Tips

- Cache session parsing: Parse JWT once and reuse
- Use RegExp for path matching instead of multiple string comparisons
- Apply rate limiting selectively to API routes only
- Lazy-load heavy middleware (e.g., logger)

## Troubleshooting

### Middleware not executing

Make sure your `config.matcher` includes the paths you want to protect.

```typescript
export const config = {
  matcher: [
    // Include all except these
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
```

### Headers not merging properly

When combining with other middleware, merge headers explicitly:

```typescript
if (customResponse) {
  otherResponse.headers.forEach((value, key) => {
    if (!customResponse.headers.has(key)) {
      customResponse.headers.set(key, value);
    }
  });
  return customResponse;
}
```

### Session not found

Ensure you're reading session from the correct cookie:

```typescript
const sessionCookie = request.cookies.get('nguard-session')?.value;
// or your custom cookie name
const sessionCookie = request.cookies.get('YOUR_COOKIE_NAME')?.value;
```

## See Also

- [Middleware Examples](./examples/middleware-basic.ts)
- [next-intl Integration](./examples/middleware-with-intl.ts)
- [Security Best Practices](./BEST-PRACTICES.md)
