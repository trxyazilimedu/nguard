# CLI Kurulum Rehberi

İnteraktif CLI sihirbazı, Nguard'ı Next.js 16+ projenizde otomatik olarak yapılandırır.

## Kurulum

```bash
npm install nguard
npx nguard-setup
```

## Sihirbaz Ne Yapıyor?

Sihirbaz birkaç soru sorar ve şunları oluşturur:

1. **lib/auth.ts** - Sunucu tarafı kimlik doğrulama araçları
2. **API rotaları** - `/api/auth/login`, `/api/auth/logout`, `/api/auth/validate`, `/api/auth/refresh`
3. **proxy.ts** - Next.js 16 ara yazılımı
4. **.env.local.example** - Çevre değişkenleri şablonu
5. **tsconfig.json güncellemeleri** - Yol takma adları (`@/*`)

## Etkileşimli Kurulum Süreci

### Adım 1: Onay

Sihirbaz oluşturacağı şeyleri gösterir ve onay ister:

```
⚠️ Sihirbaz şunları oluşturacak/güncelleyecek:
- lib/auth.ts
- app/api/auth/ rotaları
- proxy.ts
- .env.local.example

Devam et? (e/h):
Sorumluluğu kabul ediyor musun? (e/h):
```

### Adım 2: Proje Yapılandırması

```
TypeScript projesi mi? (e/h):
App dizini (varsayılan: app):
Çerez adı (varsayılan: nguard-session):
Ortam (varsayılan: development):
```

### Adım 3: Rotaları Seç

Hangi kimlik doğrulama uç noktalarını oluşturacağını seç:

```
/api/auth/login oluştur? (önerilen) (e/h):
/api/auth/logout oluştur? (önerilen) (e/h):
/api/auth/validate oluştur? (önerilen) (e/h):
/api/auth/refresh oluştur? (e/h):
```

## Kurulum Sonrası

### 1. Çevre Değişkenlerini Yapılandır

```bash
cp .env.local.example .env.local
```

`.env.local`'ı düzenle:

```env
NGUARD_SECRET=32-karakterlik-sırrın
BACKEND_API_URL=http://localhost:8080/api
NODE_ENV=development
```

Sır oluştur:
```bash
openssl rand -base64 32
```

### 2. SessionProvider Ekle

`app/layout.tsx`'de:

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

### 3. Kullanmaya Başla

**Server Component:**
```typescript
import { auth } from '@/lib/auth';

export default async function Page() {
  const session = await auth();
  return <div>Merhaba {session?.email}</div>;
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

## Rotaları Özelleştir

Oluşturulan rotaları düzenle ve backend mantığını ekle:

```typescript
// app/api/auth/login/route.ts
import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

const BACKEND_API_URL = process.env.BACKEND_API_URL || '';

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    // Backend'i çağır
    const res = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) throw new Error('Auth failed');

    const data = await res.json();

    // Backend verisi ile oturum oluştur
    const { session, setCookieHeader } = await nguard.createSession({
      ...data,
      expires: Date.now() + 24 * 60 * 60 * 1000,
    });

    return NextResponse.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Giriş başarısız' },
      { status: 401 }
    );
  }
}
```

## Ara Yazılım Ekle

`proxy.ts`'yi düzenle ve güvenlik ara yazılımı ekle:

```typescript
import { compose, requireAuth, logger } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger({ onLog: (data) => console.log(data) }),
    // requireAuth, // Etkinleştir: rotaları koru
  );

  const response = await middleware(request, null);
  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

## Sorun Giderme

| Sorun | Çözüm |
|-------|--------|
| TypeScript hataları | `tsconfig.json`'da `@/*` yol takma adını kontrol et |
| Rotalar bulunamıyor | Dosyaların `app/api/auth/[route]/route.ts`'de olduğunu kontrol et |
| Oturum kalıcı değil | `.env.local`'da `NGUARD_SECRET` ayarlandığını kontrol et |
| İçe aktarma hataları | `@/*` takma adını kontrol et, dev sunucuyu yeniden başlat |

## Dosya Yapısı

```
projeni/
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
└── tsconfig.json (güncellendi)
```

## Ayrıca Bak

- [Hızlı Başlangıç](./QUICKSTART.md) - Hooks'u öğren
- [API Referansı](./API-CLIENT.md) - Tüm metodlar
- [Ara Yazılım Rehberi](./MIDDLEWARE.md) - Ara yazılım desenleri
- [Doğrulama Rehberi](./VALIDATION.md) - Oturum doğrula
