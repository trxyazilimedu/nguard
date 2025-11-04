# Nguard CLI Kurulum Rehberi

Nguard CLI Setup Wizard, Nguard kimlik doğrulamasının Next.js 16+ projenize entegre edilmesini basit etkileşimli bir sihirbazla otomatikleştirir.

## Hızlı Başlangıç

```bash
# Nguard'ı yükle
npm install nguard

# Setup sihirbazını çalıştır
npx nguard-setup
```

Hepsi bu kadar! Sihirbaz sizi rehberlik edecek ve tüm gerekli dosyaları oluşturacak.

## Neler Oluşturulur?

### 1. **lib/auth.ts** (veya lib/auth.js)

Sunucu tarafı kimlik doğrulama araçları:
- `nguard` - Başlatılmış sunucu örneği
- `auth()` - Server Components'ta mevcut oturumu al
- Yardımcı fonksiyonlar: `createSession()`, `clearSession()`, `updateSession()`, `validateSession()`

### 2. **API Rotaları** - `app/api/auth/[route]/route.ts`

Otomatik oluşturulan uç noktalar (seçiminize göre):

- **POST /api/auth/login** - Oturum oluştur
- **POST /api/auth/logout** - Oturumu temizle
- **GET /api/auth/validate** - Oturum geçerliliğini kontrol et
- **POST /api/auth/refresh** - Oturum süresini uzat

### 3. **proxy.ts** (Next.js 16+)

`middleware.ts` yerine geçer. Ara yazılımını kur:
- Kimlik doğrulama gereksinimleri
- Rol tabanlı erişim kontrolü
- İstek günlüğü
- CORS başlıkları
- Oturum doğrulaması

### 4. **.env.local.example**

Çevre değişkenleri şablonu:
```env
NGUARD_SECRET=32-karakterlik-sırrın
BACKEND_API_URL=http://localhost:8080/api
NODE_ENV=development
```

### 5. **tsconfig.json** Güncellemeleri

Daha temiz içe aktarımlar için yol takma adları:
```typescript
// Öncesi: import { auth } from '../../../lib/auth'
// Sonrası: import { auth } from '@/lib/auth'
```

## Etkileşimli Kurulum Süreci

### Adım 1: Onay

```
⚠️ SORUMLULUK BEYANATI:
Sihirbaz projenizde şu dosyaları oluşturacak/güncelleyecek:
- lib/auth.ts
- app/api/auth/ rotaları
- proxy.ts
- .env.local.example

Devam etmek istiyor musunuz? (e/h):
Tüm sorumluluk seni mi? (e/h):
```

### Adım 2: Proje Yapılandırması

```
Bu bir TypeScript projesi mi? (e/h):
App dizin yolu (varsayılan: app):
Oturum çerezi adı (varsayılan: nguard-session):
Ortam (varsayılan: development):
```

### Adım 3: Kimlik Doğrulama Rotalarını Seç

Hangi rotaları oluşturacağını seç:
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

JWT sırrı oluştur:
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

### 3. Componentlerinizde Kullan

**Server Component:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();
  if (!session) return <div>Giriş yapmamışsın</div>;

  return <div>Hoş geldin {session.email}</div>;
}
```

**Client Component:**
```typescript
'use client';

import { useSession, useLogin, useLogout } from 'nguard/client';

export default function Profile() {
  const { session } = useSession();
  const { login, isLoading } = useLogin();
  const { logout } = useLogout();

  if (!session) {
    return (
      <form onSubmit={async (e) => {
        e.preventDefault();
        await login({
          email: 'kullanici@example.com',
          password: 'sifre',
        });
      }}>
        <input type="email" placeholder="E-posta" required />
        <input type="password" placeholder="Şifre" required />
        <button disabled={isLoading}>Giriş Yap</button>
      </form>
    );
  }

  return (
    <div>
      <p>{session.email} olarak giriş yaptın</p>
      <button onClick={logout}>Çıkış Yap</button>
    </div>
  );
}
```

### 4. API Rotalarını Özelleştir

`app/api/auth/login/route.ts`'yi düzenle ve backend mantığını ekle:

```typescript
// app/api/auth/login/route.ts
import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

const BACKEND_API_URL = process.env.BACKEND_API_URL || '';

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    // Backend'i çağır
    const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!backendResponse.ok) {
      throw new Error('Kimlik doğrulama başarısız');
    }

    const backendData = await backendResponse.json();

    // Backend verisi ile oturum oluştur
    const { session, setCookieHeader } = await nguard.createSession({
      ...backendData,
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

### 5. Ara Yazılım Ekle

`proxy.ts`'yi düzenle ve güvenlik ara yazılımı ekle:

```typescript
import { compose, requireAuth, logger } from 'nguard';
import { NextRequest, NextResponse } from 'next/server';

export async function proxy(request: NextRequest) {
  const session = null; // Gerekirse çerezlerden çıkar

  const middleware = compose(
    logger({
      onLog: (data) => console.log('[İstek]', data.method, data.path),
    }),
    // Korunan rotalar için requireAuth ekle:
    // requireAuth,
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico|public).*)'],
};
```

## Özelleştirme Seçenekleri

### Çerez Adını Değiştir

```bash
# .env.local'ı düzenle
NGUARD_COOKIE_NAME=benim-oturumum
```

### TypeScript Yol Takma Adlarını Ayarla

CLI tarafından zaten yapıldı, ama `tsconfig.json`'a manuel olarak eklemek için:

```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./*"]
    }
  }
}
```

### Özel Oturum Verisi

Oturum herhangi bir veri yapısını kabul eder:

```typescript
await nguard.createSession({
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  permissions: ['read', 'write'],
  customField: 'herhangi bir değer',
  expires: Date.now() + 24 * 60 * 60 * 1000,
});
```

## Sorun Giderme

| Sorun | Çözüm |
|-------|--------|
| TypeScript hataları | `tsconfig.json`'da `@/*` yol takma adı olduğundan emin ol, `npm run build` çalıştır |
| Oturum kalıcı değil | `.env.local`'da `NGUARD_SECRET` olduğunu kontrol et, backend çalışıyor mu? |
| Rotalar çalışmıyor | `app/api/auth/[route]/route.ts`'da dosya olduğunu doğrula |
| İçe aktarma hataları | `tsconfig.json`'da `@/*` yol takma adını kontrol et, dev sunucuyu yeniden başlat |

## Kurulum Sonrası Dosya Yapısı

```
projeni/
├── app/
│   ├── api/auth/
│   │   ├── login/route.ts
│   │   ├── logout/route.ts
│   │   ├── validate/route.ts
│   │   └── refresh/route.ts
│   ├── layout.tsx (SessionProvider ile)
│   └── page.tsx
├── lib/
│   └── auth.ts
├── proxy.ts
├── .env.local
├── .env.local.example
├── tsconfig.json (güncellendi)
└── package.json
```

## Ayrıca Bak

- [API Referansı](./API-CLIENT.md) - Tüm hooks ve metodlar
- [Ara Yazılım Rehberi](./MIDDLEWARE.md) - Ara yazılım sistemi
- [Oturum Doğrulaması](./VALIDATION.md) - Doğrulama desenleri
- [SETUP-REFERANSI](../SETUP-REFERENCE.md) - Hızlı referans
