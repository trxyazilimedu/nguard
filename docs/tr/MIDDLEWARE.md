# Middleware Sistemi

Nguard esnek, bileştirilebilir bir middleware sistemi sağlar. `next-intl` ve diğer middleware kütüphaneleriyle sorunsuz çalışır.

## Genel Bakış

Middleware sistemi şu ilkelere dayanır:

- **Esnek**: Tek middleware kullan veya bileştir
- **Bileştirilebilir**: Middleware'leri istediğin sırayla zincirle
- **Uyumlu**: next-intl, i18n ve diğer middleware'lerle çalışır
- **Yazılı**: Tam TypeScript desteği
- **Girişimci Değil**: Diğer middleware'lerle çatışmaz

## Temel Kullanım

### Basit Authentication Middleware

```typescript
// middleware.ts
import { requireAuth } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function middleware(request: NextRequest) {
  const session = null; // Cookie'den veya session store'dan al
  const authMiddleware = requireAuth();

  const response = authMiddleware(request, session);

  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)',
};
```

## Mevcut Middleware'ler

### requireAuth()

Session gerektirir.

```typescript
const middleware = requireAuth();
// Dönüş: Session yoksa /login'e yönlendir
```

### requireRole(role)

Kullanıcı belirli role'e sahip olmalı.

```typescript
const middleware = requireRole('admin');
// veya birden fazla role
const middleware = requireRole(['admin', 'moderator']);
// Dönüş: 403 eğer role yoksa
```

### requirePermission(permission)

Kullanıcı belirli permission'a sahip olmalı.

```typescript
const middleware = requirePermission('users:read');
// veya birden fazla permission
const middleware = requirePermission(['posts:create', 'posts:edit']);
// Dönüş: 403 eğer permission yoksa
```

### rateLimit(config)

Kullanıcı veya IP'ye göre rate limiting.

```typescript
import { rateLimit } from 'nguard';

const middleware = rateLimit({
  maxRequests: 100,
  windowMs: 60 * 1000, // 1 dakika
});
// Dönüş: 429 (Too Many Requests)
```

### logger(config)

İsteği kaydet.

```typescript
import { logger } from 'nguard';

const middleware = logger({
  onLog: (data) => {
    console.log(`${data.method} ${data.pathname}`);
  },
});
```

### cors(config)

CORS headers'ı yönet.

```typescript
import { cors } from 'nguard';

const middleware = cors({
  allowedOrigins: ['http://localhost:3000', 'https://example.com'],
  credentials: true,
});
```

## Middleware Bileştirme

### compose()

Birden fazla middleware'i birleştir.

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

Şartlı olarak middleware çalıştır.

```typescript
import { when, requireAuth } from 'nguard';

const middleware = when(
  (req) => req.nextUrl.pathname.startsWith('/api'),
  requireAuth()
);
```

### onPath()

Sadece belirli path'ler için middleware çalıştır.

```typescript
import { onPath, requireRole } from 'nguard';

const middleware = onPath(
  /^\/admin/,  // RegExp
  requireRole('admin')
);

// veya string
const middleware = onPath('/dashboard', requireAuth());

// veya function
const middleware = onPath(
  (pathname) => pathname.startsWith('/api/protected'),
  requireAuth()
);
```

## next-intl ile Entegrasyon

Nguard middleware `next-intl` ile sorunsuz çalışır. İşte doğru kurulum:

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
  // Step 1: i18n önce uygula
  const intlResponse = intlMiddleware(request);

  // Step 2: Session'ı al
  const sessionCookie = request.cookies.get('nguard-session')?.value;
  let session: Session | null = null;
  if (sessionCookie) {
    try {
      session = JSON.parse(sessionCookie);
    } catch {}
  }

  // Step 3: Nguard middleware uygula
  const authMiddleware = compose(
    requireAuth(),
    requireRole('user')
  );

  const authResponse = await authMiddleware(request, session);

  if (authResponse) {
    // Headers'ı birleştir
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

## Hata Yönetimi

### withErrorHandling()

Middleware'i hata yönetimi ile sarıla.

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

## Özel Middleware

Kendi middleware'ini oluştur:

```typescript
import { NguardMiddleware } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';
import { Session } from 'nguard';

const customMiddleware: NguardMiddleware = (request, session) => {
  // Senin logiğin

  if (someCondition) {
    return NextResponse.json(
      { error: 'Forbidden' },
      { status: 403 }
    );
  }

  // Devam etmek için hiçbir şey döndürme
};

export async function middleware(request: NextRequest) {
  const session = getSession(request);
  const response = customMiddleware(request, session);

  return response || NextResponse.next();
}
```

## Session Yapısı

Session objen herhangi bir yapıya sahip olabilir. Yaygın pattern'ler:

```typescript
// Basit session
{
  id: 'user-123',
  email: 'user@example.com',
  name: 'John Doe',
  expires: 1234567890000
}

// Role ile
{
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  expires: 1234567890000
}

// Permission'larla
{
  id: 'user-123',
  permissions: ['users:read', 'posts:create'],
  expires: 1234567890000
}

// Karmaşık yapı
{
  id: 'user-123',
  email: 'user@example.com',
  profile: {
    name: 'John Doe',
    avatar: 'https://...',
  },
  role: 'admin',
  permissions: ['users:read', 'posts:create'],
  expires: 1234567890000
}
```

## En İyi Uygulamalar

1. **Doğru sırada uygula**: i18n önce, sonra authentication
2. **Session'ı erken al**: Başında cookie'den çıkar
3. **compose kullan**: İlgili middleware'leri grupla
4. **Hataları yönet**: `withErrorHandling()` kullan
5. **Test et**: Diğer middleware'lerle test et

## Sorun Giderme

### Middleware çalışmıyor

`config.matcher` kontrol et.

```typescript
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
```

### Session'ı bulamıyor

Doğru cookie'den okuduğundan emin ol:

```typescript
const sessionCookie = request.cookies.get('nguard-session')?.value;
```
