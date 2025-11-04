# Oturum Doğrulaması

Oturumu doğrula ve hala geçerli olup olmadığını kontrol et.

## Doğrulama Uç Noktaları

CLI doğrulama uç noktalarını otomatik olarak oluşturur. `/api/auth/validate`'de mevcuttur.

### GET /api/auth/validate

Cookie'lerden oturumu kontrol et.

**Yanıt (Geçerli):**
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

**Yanıt (Geçersiz):**
```json
{
  "valid": false,
  "error": "Oturum süresi doldu",
  "expiresIn": -3600000
}
```

### POST /api/auth/validate

İstek gövdesinden bir token'ı doğrula.

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
  "session": { /* ... */ },
  "expiresIn": 3600000
}
```

### HEAD /api/auth/validate

Yanıt gövdesi olmadan hızlı doğrulama.

**Döndürür:**
- `200` - Oturum geçerli
- `401` - Oturum geçersiz veya süresi doldu

## İstemci Tarafı Doğrulaması

### useValidateSession Hook

```typescript
'use client';

import { useValidateSession } from 'nguard/client';

export function CheckSession() {
  const { validate, isValid, validationResult } = useValidateSession();

  return (
    <div>
      <button onClick={() => validate()}>Oturumu Kontrol Et</button>

      {isValid && (
        <p>
          ✅ Oturum geçerli
          {validationResult?.expiresIn && (
            <span> - {Math.round(validationResult.expiresIn / 1000)}s içinde süresi dolar</span>
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

### Manuel Doğrulama

```typescript
'use client';

async function checkSession() {
  const response = await fetch('/api/auth/validate');
  const data = await response.json();

  if (data.valid) {
    console.log('Oturum geçerli');
    console.log('Süresi bitmesi:', data.expiresIn, 'ms');
  } else {
    console.log('Oturum geçersiz:', data.error);
  }
}
```

## Uygulama Yüklenişinde Otomatik Yenileme

Uygulama başladığında oturumu kontrol et ve geçersizse yönlendir:

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

## Sona Ermeden Önce Yenile

Oturumu periyodik olarak kontrol et ve gerekirse yenile:

```typescript
'use client';

import { useEffect } from 'react';
import { useValidateSession } from 'nguard/client';

export function SessionManager() {
  const { validate, validationResult } = useValidateSession();

  useEffect(() => {
    // Her dakika kontrol et
    const interval = setInterval(async () => {
      await validate();

      if (!validationResult?.valid) {
        // Giriş sayfasına yönlendir
        window.location.href = '/login';
        return;
      }

      // 5 dakika içinde sona erecekse yenile
      if (validationResult.expiresIn < 5 * 60 * 1000) {
        await fetch('/api/auth/refresh', { method: 'POST' });
      }
    }, 60 * 1000);

    return () => clearInterval(interval);
  }, [validate, validationResult]);

  return null;
}
```

## Sunucu Tarafı Doğrulaması

```typescript
import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const cookieString = request.headers.get('cookie') || '';
  const session = await nguard.validateSession(cookieString);

  if (!session) {
    return NextResponse.json(
      { valid: false, error: 'Geçerli oturum yok' },
      { status: 401 }
    );
  }

  const now = Date.now();
  const expiresIn = session.expires - now;

  if (expiresIn < 0) {
    return NextResponse.json(
      { valid: false, error: 'Oturum süresi doldu', expiresIn },
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

## Yanıt Yapısı

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
  expiresIn?: number; // millisaniye
}
```

## Hata Mesajları

| Hata | Anlamı |
|------|--------|
| `Geçerli oturum yok` | Oturum cookie'si bulunamadı |
| `Geçersiz token` | Token hatalı biçimde veya değiştirildi |
| `Oturum süresi doldu` | Token sona erme zamanı geçti |
| `Doğrulama başarısız` | Sunucu doğrulama sırasında hata |

## En İyi Uygulamalar

1. **Uygulama yüklenişinde doğrula** - Uygulama başladığında oturumu kontrol et
2. **Sona Ermesini Zarif Şekilde Yönet** - Sona ermeden önce yenile
3. **HEAD İsteğini Kullan** - Hızlı durum kontrolleri için
4. **expiresIn'i İzle** - Oturumun ne zaman sona ereceğini bil
5. **Otomatik Yenile** - Sona ermeden önce oturumu yenile

## Örnek: Korumalı Rota

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

  if (!ready) return <div>Oturum kontrol ediliyor...</div>;
  if (!isValid) return <div>Yönlendiriliyor...</div>;

  return <div>Korumalı içerik buraya gelir</div>;
}
```

## Ayrıca Bak

- [Hızlı Başlangıç](./QUICKSTART.md) - Hook'ları öğren
- [CLI Kurulum](./CLI-SETUP.md) - Kurulum
- [API Referansı](./API-CLIENT.md) - Tüm metodlar
- [Ara Yazılım Rehberi](./MIDDLEWARE.md) - Güvenlik ekle
