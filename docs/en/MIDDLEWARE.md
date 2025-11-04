# Middleware Guide

Add authentication and security middleware to your Next.js 16 app using `proxy.ts`.

## Basics

All middleware work with the `compose()` function:

```typescript
import { compose, requireAuth, logger } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger(),
    requireAuth,
  );

  const response = await middleware(request, null);
  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

## Built-in Middleware

### requireAuth

Require valid session. Redirects to `/login` if not authenticated.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(requireAuth);
  const response = await middleware(request, null);
  return response || NextResponse.next();
}
```

### requireRole

Require specific role. Returns 403 if role doesn't match.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    requireRole(['admin', 'moderator']),
  );
  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### requirePermission

Require specific permission. Returns 403 if permission doesn't match.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    requirePermission(['posts:create', 'posts:edit']),
  );
  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### logger

Log all requests.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger({
      onLog: (data) => console.log(`[${data.method}] ${data.path}`),
    }),
  );
  const response = await middleware(request, null);
  return response || NextResponse.next();
}
```

### cors

Add CORS headers.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    cors({
      origin: ['http://localhost:3000'],
      credentials: true,
    }),
  );
  const response = await middleware(request, null);
  return response || NextResponse.next();
}
```

### rateLimit

Rate limit requests per IP or user.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    rateLimit({
      maxRequests: 100,
      windowMs: 60 * 1000, // 1 minute
    }),
  );
  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### injectHeaders

Inject custom headers.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    injectHeaders({
      'X-Custom-Header': 'value',
    }),
  );
  const response = await middleware(request, null);
  return response || NextResponse.next();
}
```

## Composing Middleware

Combine multiple middleware:

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger(),
    cors(),
    requireAuth,
    requireRole(['admin']),
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Conditional Middleware

Apply middleware conditionally:

```typescript
import { compose, when, requireAuth } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    // Only require auth for /admin paths
    when(
      request.nextUrl.pathname.startsWith('/admin'),
      requireAuth,
    ),
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Path-based Middleware

Apply middleware to specific paths:

```typescript
import { compose, onPath, requireAuth } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    onPath(/^\/admin/, requireAuth),
    onPath(/^\/api/, logger()),
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Custom Middleware

Create your own middleware:

```typescript
const customAuth = (req, session) => {
  if (req.nextUrl.pathname.startsWith('/protected')) {
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }
  }
  return null;
};

export async function proxy(request: NextRequest) {
  const middleware = compose(customAuth);
  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Error Handling

Wrap middleware with error handling:

```typescript
import { compose, withErrorHandling, requireAuth } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    withErrorHandling(requireAuth, (error) => {
      console.error('Auth error:', error);
      return new NextResponse('Auth failed', { status: 401 });
    }),
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Full Example

```typescript
import { compose, logger, requireAuth, requireRole, cors } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function proxy(request: NextRequest) {
  // Extract session from cookies if needed
  const session = null; // You would parse this from cookies

  const middleware = compose(
    // Log all requests
    logger({
      onLog: (data) => console.log(`[${data.method}] ${data.path}`),
    }),

    // Add CORS headers
    cors({
      origin: ['http://localhost:3000'],
      credentials: true,
    }),

    // Require auth for /dashboard
    when(
      request.nextUrl.pathname.startsWith('/dashboard'),
      requireAuth,
    ),

    // Require admin role for /admin
    when(
      request.nextUrl.pathname.startsWith('/admin'),
      requireRole(['admin']),
    ),
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

## See Also

- [Quick Start](./QUICKSTART.md) - Learn hooks
- [CLI Setup](./CLI-SETUP.md) - Installation
- [API Reference](./API-CLIENT.md) - All methods
- [Validation Guide](./VALIDATION.md) - Check session
