# Nguard CLI Kurulum Rehberi

Nguard CLI Kurulum Sihirbazı, Nguard kimlik doğrulamasının Next.js 16+ projenize entegre edilmesini otomatikleştirir. Tüm gerekli yapılandırma dosyalarını, API rotalarını ve TypeScript türlerini oluşturur.

## Hızlı Başlangıç

```bash
npm run setup
```

Hepsi bu kadar! Etkileşimli sihirbaz sizi kurulum sürecinde rehberlik edecek.

## Neler Oluşturulur?

CLI, Next.js projenizde aşağıdaki dosyaları oluşturur:

### 1. **lib/auth.ts** (veya JavaScript projeleri için lib/auth.js)

Sunucu tarafı kimlik doğrulama araçları şunları içerir:
- `nguard` - Başlatılmış sunucu örneği
- `auth()` - Server Components'ta mevcut oturumu almak için async fonksiyon
- Yardımcı fonksiyonlar: `createSession()`, `clearSession()`, `updateSession()`, `validateSession()`

**Örnek:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();

  if (!session) {
    return <div>Kimlik doğrulanmamış</div>;
  }

  return <div>Hoş geldin {session.email}</div>;
}
```

### 2. **app/api/auth/[route]/route.ts** - API Rotaları

Sihirbaz, aşağıdaki kimlik doğrulama uç noktalarından bir veya daha fazlasını oluşturur:

#### POST /api/auth/login
Kullanıcı kimliklerini doğrular ve oturum oluşturur:
```json
İstek:
{
  "email": "kullanici@example.com",
  "password": "sifre123"
}

Yanıt:
{
  "session": {
    "id": "user-123",
    "email": "kullanici@example.com",
    "role": "admin"
  }
}
```

#### POST /api/auth/logout
Oturumu temizler ve kimlik doğrulama çerezini kaldırır:
```json
Yanıt:
{ "ok": true }
```

#### GET /api/auth/validate
Geçerli oturumu çerezlerden doğrular:
```json
Yanıt:
{
  "valid": true,
  "session": { ... },
  "expiresIn": 3600000
}
```

#### POST /api/auth/refresh
Oturum süresini yeniler:
```json
Yanıt:
{ "ok": true }
```

### 3. **proxy.ts** (Next.js 16+)

Eski `middleware.ts` dosyasının yerine geçer. Buraya şu gibi ara yazılımları ekleyebilirsiniz:
- Kimlik doğrulama gereksinimleri
- Rol tabanlı erişim kontrolü
- İstek günlüğü
- CORS başlıkları
- Oturum doğrulaması

Oluşturulan proxy.ts şunları içerir:
- Çerezlerden oturum çıkarma
- Temel ara yazılım bileşimi kurulumu
- Özel ara yazılım yer tutucu

**Not:** Next.js 16, ağ sınırını açıkça belirtmek için `middleware.ts` yerine `proxy.ts` kullanır.

### 4. **.env.local.example**

Çevre değişkenleri şablonu:

```env
# JWT Sırrı (minimum 32 karakter)
# Şunu ile oluştur: openssl rand -base64 32
NGUARD_SECRET=sifreli-secret-min-32-chars

# Backend API URL'si
BACKEND_API_URL=http://localhost:8080/api

# Ortam
NODE_ENV=development

# Oturum çerezi yapılandırması (isteğe bağlı)
# NGUARD_COOKIE_NAME=nguard-session
# NGUARD_COOKIE_SECURE=true
# NGUARD_COOKIE_SAME_SITE=Strict
```

### 5. **tsconfig.json** (Yol Takma Adı)

TypeScript projeleri için sihirbaz, tsconfig.json'unuzu yol takma adı ekleyerek günceller:

```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./*"]
    }
  }
}
```

Bu, daha temiz içe aktarımlar sağlar:
```typescript
// Öncesi
import { auth } from '../../../lib/auth';

// Sonrası
import { auth } from '@/lib/auth';
```

## Etkileşimli Kurulum Süreci

### Adım 1: Hoş Geldiniz & Sorumluluk Beyanı

Sihirbaz, dosya değişiklikleri hakkında bir sorumluluk beyanı görüntüler:
- `lib/auth.ts` veya `lib/auth.js` oluşturur
- `app/api/auth/` altında API rotaları oluşturur
- `proxy.ts` oluşturur veya günceller
- Çevre değişkenleri şablonu ekler

### Adım 2: Sorumluluk Onayı

Onaylamanız gerekir:
1. "Devam etmek istiyor musunuz? Bu işlem geri alınamaz." → **e**
2. "Bu değişikliklerden tam sorumluluğu kabul ediyor ve riskleri anlıyor musunuz?" → **e**

### Adım 3: Proje Yapılandırması

Sihirbaz sorar:

```
📋 PROJE YAPILANDIRMASI

Proje Kökü: /path/to/your/project

Bu bir TypeScript projesi mi? (e/h):
```

**TypeScript vs JavaScript:**
- **e** - Tam tür desteği ile `.ts` dosyaları oluşturur
- **h** - JSDoc yorumları ile `.js` dosyaları oluşturur

### Adım 4: Yolları Özelleştir

```
App dizin yolu (varsayılan: app):
```

Varsayılanı kullanmak için Enter tuşuna basın veya özel yol belirtin (ör. `src/app`).

### Adım 5: Oturum Yapılandırması

```
Oturum için çerez adı (varsayılan: nguard-session):
```

Oturum çerezi adını özelleştirin veya varsayılan için Enter tuşuna basın.

### Adım 6: Ortam Seçimi

```
Ortam (development/production, varsayılan: development):
```

`.env.local.example`'deki `NODE_ENV`'yi etkiler.

### Adım 7: Kimlik Doğrulama Rotalarını Seç

Hangi rotaları oluşturacağınızı seçin:

```
/api/auth/login oluştur? (önerilen) (e/h):
/api/auth/logout oluştur? (önerilen) (e/h):
/api/auth/validate oluştur? (önerilen) (e/h):
/api/auth/refresh oluştur? (e/h):
```

- **login/logout/validate** - Çoğu proje için önerilen
- **refresh** - İsteğe bağlı, oturum uzatması için

## Kurulum Sonrası

### 1. Çevre Değişkenlerini Ayarla

```bash
cp .env.local.example .env.local
```

`.env.local`'u yapılandırmanızla düzenleyin:
- JWT sırrı oluştur: `openssl rand -base64 32`
- Backend API URL'nizi ayarla
- Çerez ayarlarını yapılandır

### 2. Nguard Paketini Yükle

```bash
npm install nguard
```

### 3. Layout'unuzu Güncelle

`app/layout.tsx`'de:

```typescript
'use client';

import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <SessionProvider>
          {children}
        </SessionProvider>
      </body>
    </html>
  );
}
```

### 4. Kimlik Doğrulamayı Kullanmaya Başla

**Server Components'te:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();
  if (!session) return <div>Kimlik doğrulanmamış</div>;

  return <div>Hoş geldin {session.email}</div>;
}
```

**Client Components'te:**
```typescript
'use client';

import { useSession, useLogin } from 'nguard/client';

export default function LoginForm() {
  const { session, loading } = useSession();
  const { login, isLoading } = useLogin();

  const handleLogin = async (credentials) => {
    const response = await login(credentials);
    if (response.session) {
      // Başarı
    }
  };

  return (
    // Login form JSX'iniz
  );
}
```

### 5. Kurulumunuzu Test Et

```bash
npm run dev
```

`http://localhost:3000` ziyaret edin ve kimlik doğrulama akışını test edin.

## Kurulum Sonrası Özelleştirme

### API Rotalarını Değiştir

Özel mantık eklemek için oluşturulan rota dosyalarını düzenleyin:

```typescript
// app/api/auth/login/route.ts
export async function POST(request: NextRequest) {
  const { email, password } = await request.json();

  // Özel kimlik doğrulama mantığınızı ekleyin

  const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  // Yanıtı işle
}
```

### Ara Yazılım Ekle

Kimlik doğrulama ara yazılımı eklemek için `proxy.ts`'yi düzenleyin:

```typescript
import { compose, requireAuth, logger } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger({
      onLog: (data) => console.log(data),
    }),
    requireAuth, // Kimlik doğrulama gerekli
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

### Çerez Ayarlarını Değiştir

`.env.local`'u güncelleyin:

```env
NGUARD_COOKIE_NAME=ozel-session-adi
NGUARD_COOKIE_SECURE=true        # Yalnızca HTTPS
NGUARD_COOKIE_SAME_SITE=Strict  # CSRF koruması
```

## Sorun Giderme

### Kurulum Sonrası TypeScript Hataları

TypeScript hataları alırsanız:

1. `tsconfig.json`'da `@/*` yol takma adı olduğundan emin olun
2. Çalıştır: `npm run build` derlemeyi doğrulamak için
3. `dist/` oluşturulduğunu kontrol edin

### Oturum Kalıcı Değil

1. `.env.local`'da `NGUARD_SECRET` ayarlandığını doğrulayın
2. Backend'in `/auth/login`'e yanıt verip vermediğini kontrol edin
3. Tarayıcı DevTools'ta çerezleri inceleyin

### Rotalar Çalışmıyor

1. Dosyaların doğru konumda olduğunu doğrulayın: `app/api/auth/[route]/route.ts`
2. `Next.js 16+` yüklü olduğunu kontrol edin
3. Geliştirme sunucusunu yeniden başlat: `npm run dev`

### İçe Aktarma Hataları

"@/lib/auth" bulunamıyor hatasını alırsanız:

1. `lib/auth.ts` oluşturulduğunu doğrulayın
2. `tsconfig.json`'da `@/*` yol takma adı olup olmadığını kontrol edin
3. İçe aktarım yaparken yapı klasöründe olmadığınızdan emin olun

## CLI Seçenekleri

### Yardım

```bash
npm run setup -- --help
```

### İnteraktif Olmayan Modu Atla (Gelecek)

Şu anda, kurulum her zaman etkileşimli modda çalışır. Non-interaktif mod gelecekteki sürümlere eklenebilir.

## Kurulum Sonrası Dosya Yapısı

```
your-project/
├── app/
│   ├── api/
│   │   └── auth/
│   │       ├── login/
│   │       │   └── route.ts
│   │       ├── logout/
│   │       │   └── route.ts
│   │       ├── validate/
│   │       │   └── route.ts
│   │       └── refresh/
│   │           └── route.ts
│   └── layout.tsx
├── lib/
│   └── auth.ts              ← Sunucu kimlik doğrulama araçları
├── proxy.ts                  ← Ara yazılım (Next.js 16)
├── .env.local               ← Çevre değişkenleri
├── .env.local.example       ← Şablon (oluşturuldu)
├── tsconfig.json            ← @/* ile güncellendi
└── package.json
```

## Sonraki Adımlar

1. **[Ara Yazılım Belgeleri](./MIDDLEWARE.md)** - Ara yazılım sistemi hakkında bilgi
2. **[Validasyon Belgeleri](./VALIDATION.md)** - Oturum doğrulaması uygulaması
3. **[API Referansı](./API-SERVER.md)** - Tam API belgeleri
4. **[Örnekler](../examples/)** - Gerçek dünya uygulama örnekleri

## Destek

Sorular veya sorunlar için:
- GitHub Issues: https://github.com/trxyazilimedu/nguard/issues
- Belgeler: https://github.com/trxyazilimedu/nguard
