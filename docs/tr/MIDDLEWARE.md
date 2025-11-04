# Ara Yazılım Rehberi

Next.js 16 uygulamanıza `proxy.ts` kullanarak kimlik doğrulama ve güvenlik ara yazılımı ekle.

## Temel Bilgiler

Tüm ara yazılımlar `compose()` fonksiyonu ile çalışır:

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

## Yerleşik Ara Yazılımlar

### requireAuth

Geçerli oturum gerekli. Kimlik doğrulanmazsa `/login`'e yönlendir.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(requireAuth);
  const response = await middleware(request, null);
  return response || NextResponse.next();
}
```

### requireRole

Belirli rol gerekli. Rol eşleşmezse 403 döndür.

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

Belirli izin gerekli. İzin eşleşmezse 403 döndür.

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

Tüm istekleri günlüğe al.

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

CORS header'ları ekle.

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

İstekleri IP veya kullanıcı başına sınırla.

```typescript
export async function proxy(request: NextRequest) {
  const middleware = compose(
    rateLimit({
      maxRequests: 100,
      windowMs: 60 * 1000, // 1 dakika
    }),
  );
  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### injectHeaders

Özel header'lar ekle.

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

## Ara Yazılımları Birleştirme

Birden fazla ara yazılımı birleştir:

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

## Koşullu Ara Yazılım

Ara yazılımı koşullu uygula:

```typescript
import { compose, when, requireAuth } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    // Sadece /admin yolları için kimlik doğrulama gerekli
    when(
      request.nextUrl.pathname.startsWith('/admin'),
      requireAuth,
    ),
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Yola Dayalı Ara Yazılım

Ara yazılımı belirli yollara uygula:

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

## Özel Ara Yazılım

Kendi ara yazılımını oluştur:

```typescript
const customAuth = (req, session) => {
  if (req.nextUrl.pathname.startsWith('/protected')) {
    if (!session) {
      return new NextResponse('Yetkisiz', { status: 401 });
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

## Hata Yönetimi

Ara yazılımı hata işleme ile sarıp kapat:

```typescript
import { compose, withErrorHandling, requireAuth } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    withErrorHandling(requireAuth, (error) => {
      console.error('Auth hatası:', error);
      return new NextResponse('Kimlik doğrulama başarısız', { status: 401 });
    }),
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

## Tam Örnek

```typescript
import { compose, logger, requireAuth, requireRole, cors } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function proxy(request: NextRequest) {
  // Gerekirse cookie'lerden oturumu çıkar
  const session = null; // Bunu cookie'lerden ayrıştırırsın

  const middleware = compose(
    // Tüm istekleri günlüğe al
    logger({
      onLog: (data) => console.log(`[${data.method}] ${data.path}`),
    }),

    // CORS header'ları ekle
    cors({
      origin: ['http://localhost:3000'],
      credentials: true,
    }),

    // /dashboard için kimlik doğrulama gerekli
    when(
      request.nextUrl.pathname.startsWith('/dashboard'),
      requireAuth,
    ),

    // /admin için admin rolü gerekli
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

## Ayrıca Bak

- [Hızlı Başlangıç](./QUICKSTART.md) - Hook'ları öğren
- [CLI Kurulum](./CLI-SETUP.md) - Kurulum
- [API Referansı](./API-CLIENT.md) - Tüm metodlar
- [Doğrulama Rehberi](./VALIDATION.md) - Oturumu kontrol et
