# Session Validation

Nguard provides comprehensive session validation capabilities for checking JWT validity on both client and server.

## Overview

Session validation helps you:
- Check if a JWT token is valid and not expired
- Get session information without requiring authentication
- Monitor session expiration
- Implement session refresh logic
- Handle expired sessions gracefully

## Validation Endpoint

### GET /api/auth/validate

Check current session validity from cookies.

**Request:**
```bash
GET /api/auth/validate
```

**Response (Valid Session):**
```json
{
  "valid": true,
  "session": {
    "id": "user-123",
    "email": "user@example.com",
    "role": "admin",
    "permissions": ["users:read", "posts:create"],
    "expires": 1704067200000
  },
  "expiresIn": 3600000
}
```

**Response (Expired/Invalid):**
```json
{
  "valid": false,
  "error": "Session expired",
  "expiresIn": -3600000
}
```

### POST /api/auth/validate

Validate a token sent in the request body.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response:**
```json
{
  "valid": true,
  "session": {
    "id": "user-123",
    "email": "user@example.com",
    "role": "admin"
  },
  "expiresIn": 3600000
}
```

### HEAD /api/auth/validate

Quick validation without response body.

**Returns:**
- `200` - Session is valid
- `401` - Session is invalid or expired

## Implementation

### Basic Endpoint

```typescript
// app/api/auth/validate/route.ts
import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    const cookieString = request.headers.get('cookie') || '';
    const session = await nguard.validateSession(cookieString);

    if (!session) {
      return NextResponse.json({
        valid: false,
        error: 'No valid session',
      });
    }

    const now = Date.now();
    if (session.expires && session.expires < now) {
      return NextResponse.json({
        valid: false,
        error: 'Session expired',
        expiresIn: session.expires - now,
      });
    }

    return NextResponse.json({
      valid: true,
      session,
      expiresIn: session.expires - now,
    });
  } catch (error) {
    return NextResponse.json(
      { valid: false, error: 'Validation failed' },
      { status: 500 }
    );
  }
}
```

## Client-Side Usage

### useValidateSession Hook

```typescript
'use client';

import { useValidateSession } from '@/hooks/useValidateSession';

export function SessionStatus() {
  const { validate, isValidating, isValid, validationResult } = useValidateSession();

  return (
    <div>
      <button onClick={() => validate()} disabled={isValidating}>
        {isValidating ? 'Checking...' : 'Check Session'}
      </button>

      {isValid && (
        <p>
          ✅ Session valid
          {validationResult?.expiresIn && (
            <span> - Expires in {Math.round(validationResult.expiresIn / 1000)} seconds</span>
          )}
        </p>
      )}

      {!isValid && validationResult?.error && (
        <p>❌ {validationResult.error}</p>
      )}
    </div>
  );
}
```

### Manual Validation

```typescript
'use client';

async function checkSession() {
  const response = await fetch('/api/auth/validate');
  const data = await response.json();

  if (data.valid) {
    console.log('Session is valid, expires in:', data.expiresIn);
  } else {
    console.log('Session invalid:', data.error);
  }
}
```

## Middleware Usage

### Basic Validation Middleware

```typescript
import { validateSession } from '@/middleware/validate';
import { compose } from 'nguard';

export async function middleware(request: NextRequest) {
  const session = getSessionFromCookie(request);

  const middleware = compose(
    validateSession,  // Check session validity
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### With Auto-Refresh

```typescript
import { validateSession, autoRefresh } from '@/middleware/validate';

export async function middleware(request: NextRequest) {
  const session = getSessionFromCookie(request);

  const middleware = compose(
    validateSession,
    autoRefresh(5 * 60 * 1000), // Refresh 5 mins before expiration
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Advanced Patterns

### Session Status in Headers

```typescript
import { sessionStatus } from '@/middleware/validate';

// Middleware adds headers:
// X-Session-Status: valid | expiring | expired | none
// X-Session-Expires-In: 3600 (seconds)
// X-User-ID: user-123

// Client reads headers
const response = await fetch('/api/some-endpoint');
const sessionStatus = response.headers.get('X-Session-Status');

if (sessionStatus === 'expiring') {
  // Show session expiring warning
}
```

### Automatic Session Refresh

```typescript
'use client';

import { useEffect } from 'react';

export function SessionManager() {
  useEffect(() => {
    // Check session every minute
    const interval = setInterval(async () => {
      const response = await fetch('/api/auth/validate');
      const data = await response.json();

      if (!data.valid) {
        // Redirect to login
        window.location.href = '/login';
        return;
      }

      // If expires within 5 minutes, refresh
      if (data.expiresIn < 5 * 60 * 1000) {
        await fetch('/api/auth/refresh', { method: 'POST' });
      }
    }, 60 * 1000);

    return () => clearInterval(interval);
  }, []);

  return null;
}
```

### Validation on Route Change

```typescript
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export function SessionGuard() {
  const router = useRouter();

  useEffect(() => {
    async function validateBeforeNavigation() {
      const response = await fetch('/api/auth/validate');
      const data = await response.json();

      if (!data.valid) {
        router.push('/login');
      }
    }

    // Validate on route changes
    window.addEventListener('popstate', validateBeforeNavigation);
    return () => window.removeEventListener('popstate', validateBeforeNavigation);
  }, [router]);

  return null;
}
```

## Response Structure

### Validation Response

```typescript
interface ValidationResponse {
  valid: boolean;
  session?: {
    id?: string;
    email?: string;
    role?: string;
    permissions?: string[];
    expires?: number;
  };
  error?: string;
  expiresIn?: number; // Milliseconds until expiration
}
```

### Error Codes

| Error | Meaning |
|-------|---------|
| `No session` | No JWT token found in cookies |
| `Invalid token` | Token is malformed or tampered |
| `Session expired` | JWT expiration time has passed |
| `Validation failed` | Server error during validation |

## Best Practices

1. **Validate on App Load**
   ```typescript
   // Check session when app initializes
   useEffect(() => {
     validateSession();
   }, []);
   ```

2. **Handle Expiration Gracefully**
   ```typescript
   if (validationResult?.error === 'Session expired') {
     // Refresh or redirect to login
   }
   ```

3. **Monitor Expiration**
   ```typescript
   const warningThreshold = 5 * 60 * 1000; // 5 minutes
   if (data.expiresIn < warningThreshold) {
     showExpirationWarning();
   }
   ```

4. **Use HEAD for Quick Checks**
   ```typescript
   // Quick check without parsing response body
   const response = await fetch('/api/auth/validate', { method: 'HEAD' });
   const isValid = response.ok;
   ```

5. **Implement Refresh Logic**
   ```typescript
   if (!data.valid && data.error === 'Session expired') {
     const refreshResponse = await fetch('/api/auth/refresh', {
       method: 'POST',
     });
     if (refreshResponse.ok) {
       // Try request again
     }
   }
   ```

## See Also

- [Middleware Documentation](./MIDDLEWARE.md)
- [API Reference](./API-SERVER.md)
- [Examples](../examples/)
