# Session Validation

Validate session and check if it's still valid.

## Validation Endpoints

The CLI creates validation endpoints automatically. They're available at `/api/auth/validate`.

### GET /api/auth/validate

Check session from cookies.

**Response (Valid):**
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

**Response (Invalid):**
```json
{
  "valid": false,
  "error": "Session expired",
  "expiresIn": -3600000
}
```

### POST /api/auth/validate

Validate a token from request body.

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
  "session": { /* ... */ },
  "expiresIn": 3600000
}
```

### HEAD /api/auth/validate

Quick validation without response body.

**Returns:**
- `200` - Session is valid
- `401` - Session is invalid or expired

## Client-Side Validation

### useValidateSession Hook

```typescript
'use client';

import { useValidateSession } from 'nguard/client';

export function CheckSession() {
  const { validate, isValid, validationResult } = useValidateSession();

  return (
    <div>
      <button onClick={() => validate()}>Check Session</button>

      {isValid && (
        <p>
          ✅ Session valid
          {validationResult?.expiresIn && (
            <span> - Expires in {Math.round(validationResult.expiresIn / 1000)}s</span>
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
    console.log('Session is valid');
    console.log('Expires in:', data.expiresIn, 'ms');
  } else {
    console.log('Session invalid:', data.error);
  }
}
```

## Auto-Refresh on App Load

Check session when app starts and redirect if invalid:

```typescript
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useValidateSession } from 'nguard/client';

export function SessionGuard() {
  const router = useRouter();
  const { validate, isValid } = useValidateSession();

  useEffect(() => {
    validate();
  }, [validate]);

  useEffect(() => {
    if (!isValid) {
      router.push('/login');
    }
  }, [isValid, router]);

  return null;
}
```

## Refresh Before Expiration

Check session periodically and refresh if needed:

```typescript
'use client';

import { useEffect } from 'react';
import { useValidateSession } from 'nguard/client';

export function SessionManager() {
  const { validate, validationResult } = useValidateSession();

  useEffect(() => {
    // Check every minute
    const interval = setInterval(async () => {
      await validate();

      if (!validationResult?.valid) {
        // Redirect to login
        window.location.href = '/login';
        return;
      }

      // Refresh if expires within 5 minutes
      if (validationResult.expiresIn < 5 * 60 * 1000) {
        await fetch('/api/auth/refresh', { method: 'POST' });
      }
    }, 60 * 1000);

    return () => clearInterval(interval);
  }, [validate, validationResult]);

  return null;
}
```

## Server-Side Validation

```typescript
import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const cookieString = request.headers.get('cookie') || '';
  const session = await nguard.validateSession(cookieString);

  if (!session) {
    return NextResponse.json(
      { valid: false, error: 'No valid session' },
      { status: 401 }
    );
  }

  const now = Date.now();
  const expiresIn = session.expires - now;

  if (expiresIn < 0) {
    return NextResponse.json(
      { valid: false, error: 'Session expired', expiresIn },
      { status: 401 }
    );
  }

  return NextResponse.json({
    valid: true,
    session,
    expiresIn,
  });
}
```

## Response Structure

```typescript
interface ValidationResponse {
  valid: boolean;
  session?: {
    id?: string;
    email?: string;
    role?: string;
    [key: string]: any;
  };
  error?: string;
  expiresIn?: number; // milliseconds
}
```

## Error Messages

| Error | Meaning |
|-------|---------|
| `No valid session` | No session cookie found |
| `Invalid token` | Token is malformed or tampered |
| `Session expired` | Token expiration time has passed |
| `Validation failed` | Server error during validation |

## Best Practices

1. **Validate on app load** - Check session when app starts
2. **Handle expiration gracefully** - Refresh before expiring
3. **Use HEAD request** - For quick status checks
4. **Monitor expiresIn** - Know when session will expire
5. **Auto-refresh** - Refresh session before expiration

## Example: Protected Route

```typescript
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useValidateSession } from 'nguard/client';

export function ProtectedPage() {
  const router = useRouter();
  const { validate, isValid } = useValidateSession();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    validate().finally(() => setReady(true));
  }, [validate]);

  useEffect(() => {
    if (ready && !isValid) {
      router.push('/login');
    }
  }, [ready, isValid, router]);

  if (!ready) return <div>Checking session...</div>;
  if (!isValid) return <div>Redirecting...</div>;

  return <div>Protected content here</div>;
}
```

## See Also

- [Quick Start](./QUICKSTART.md) - Learn hooks
- [CLI Setup](./CLI-SETUP.md) - Installation
- [API Reference](./API-CLIENT.md) - All methods
- [Middleware Guide](./MIDDLEWARE.md) - Add security
