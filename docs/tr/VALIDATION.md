# Session Validasyonu

Nguard, JWT geçerliliğini kontrol etmek için kapsamlı session validasyonu sağlar.

## Genel Bakış

Session validasyonu şunları yapmanıza yardımcı olur:
- JWT token'ın geçerli ve süresi dolmamış olduğunu kontrol etme
- Authentication gerektirmeden session bilgisini alma
- Session süresi dolma takip etme
- Session yenileme lojiğini uygulama

## Validasyon Endpoint'i

### GET /api/auth/validate

Mevcut session geçerliliğini kontrol et.

**İstek:**
```bash
GET /api/auth/validate
```

**Geçerli Session Yanıtı:**
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

**Süresi Dolmuş/Geçersiz Yanıt:**
```json
{
  "valid": false,
  "error": "Session expired",
  "expiresIn": -3600000
}
```

### POST /api/auth/validate

İstek body'sinde gönderilen token'ı valide et.

**İstek:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Yanıt:**
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

Response body'si olmadan hızlı validasyon.

**Döndürür:**
- `200` - Session geçerli
- `401` - Session geçersiz veya süresi dolmuş

## Implementasyon

### Basit Endpoint

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

## Client-Side Kullanım

### useValidateSession Hook

```typescript
'use client';

import { useValidateSession } from '@/hooks/useValidateSession';

export function SessionStatus() {
  const { validate, isValidating, isValid, validationResult } = useValidateSession();

  return (
    <div>
      <button onClick={() => validate()} disabled={isValidating}>
        {isValidating ? 'Kontrol ediliyor...' : 'Session Kontrol Et'}
      </button>

      {isValid && (
        <p>
          ✅ Session geçerli
          {validationResult?.expiresIn && (
            <span> - {Math.round(validationResult.expiresIn / 1000)} saniye içinde süresi dolar</span>
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

### Manuel Validasyon

```typescript
'use client';

async function sessionKontrolEt() {
  const response = await fetch('/api/auth/validate');
  const data = await response.json();

  if (data.valid) {
    console.log('Session geçerli, kalan süre:', data.expiresIn);
  } else {
    console.log('Session geçersiz:', data.error);
  }
}
```

## Middleware Kullanımı

### Basit Validasyon Middleware'i

```typescript
import { validateSession } from '@/middleware/validate';
import { compose } from 'nguard';

export async function middleware(request: NextRequest) {
  const session = getSessionFromCookie(request);

  const middleware = compose(
    validateSession,  // Session geçerliliğini kontrol et
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### Otomatik Yenileme ile

```typescript
import { validateSession, autoRefresh } from '@/middleware/validate';

export async function middleware(request: NextRequest) {
  const session = getSessionFromCookie(request);

  const middleware = compose(
    validateSession,
    autoRefresh(5 * 60 * 1000), // Süresi delmeden 5 dk önce yenile
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## İleri Pattern'ler

### Headers'da Session Durumu

```typescript
import { sessionStatus } from '@/middleware/validate';

// Middleware ekler:
// X-Session-Status: valid | expiring | expired | none
// X-Session-Expires-In: 3600 (saniye)
// X-User-ID: user-123

// Client headers'ı okur
const response = await fetch('/api/some-endpoint');
const status = response.headers.get('X-Session-Status');

if (status === 'expiring') {
  // Süresi dolma uyarısı göster
}
```

### Otomatik Session Yenileme

```typescript
'use client';

import { useEffect } from 'react';

export function SessionManager() {
  useEffect(() => {
    // Her dakika session kontrol et
    const interval = setInterval(async () => {
      const response = await fetch('/api/auth/validate');
      const data = await response.json();

      if (!data.valid) {
        // Login'e yönlendir
        window.location.href = '/login';
        return;
      }

      // Eğer 5 dakika içinde süresi dolacaksa yenile
      if (data.expiresIn < 5 * 60 * 1000) {
        await fetch('/api/auth/refresh', { method: 'POST' });
      }
    }, 60 * 1000);

    return () => clearInterval(interval);
  }, []);

  return null;
}
```

## Response Yapısı

### Validasyon Yanıtı

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
  expiresIn?: number; // Süresi delmesine kadar kalan milisaniye
}
```

### Hata Kodları

| Hata | Anlamı |
|------|--------|
| `No session` | Cookie'de JWT token bulunamadı |
| `Invalid token` | Token bozulmuş veya değiştirilmiş |
| `Session expired` | JWT süresi dolmuş |
| `Validation failed` | Sunucu validasyon sırasında hata |

## En İyi Uygulamalar

1. **Uygulama Yüklenirken Kontrol Et**
   ```typescript
   useEffect(() => {
     validateSession();
   }, []);
   ```

2. **Süresi Dolma Zarif Yönet**
   ```typescript
   if (validationResult?.error === 'Session expired') {
     // Yenile veya login'e yönlendir
   }
   ```

3. **Süresi Dolma Takip Et**
   ```typescript
   const warningThreshold = 5 * 60 * 1000; // 5 dakika
   if (data.expiresIn < warningThreshold) {
     showExpirationWarning();
   }
   ```

4. **Hızlı Kontrol için HEAD Kullan**
   ```typescript
   const response = await fetch('/api/auth/validate', { method: 'HEAD' });
   const isValid = response.ok;
   ```

5. **Yenileme Lojiği Uygula**
   ```typescript
   if (!data.valid && data.error === 'Session expired') {
     const refreshResponse = await fetch('/api/auth/refresh', {
       method: 'POST',
     });
     if (refreshResponse.ok) {
       // İsteği tekrar dene
     }
   }
   ```
