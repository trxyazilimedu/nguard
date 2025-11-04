# Hızlı Başlangıç

`npx nguard-setup` çalıştırdıktan sonra, Nguard'ı nasıl kullanacağını öğren.

## SessionProvider Kur

`app/layout.tsx`'de SessionProvider ile uygulamayı sarıp kapat:

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

## Server Components'te Oturum Al

```typescript
// app/dashboard/page.tsx
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();

  if (!session) {
    return <div>Lütfen giriş yapın</div>;
  }

  return (
    <div>
      <h1>Merhaba {session.email}</h1>
      <p>Role: {session.role}</p>
    </div>
  );
}
```

## Client Components'te Oturum Al

```typescript
'use client';

import { useSession } from 'nguard/client';

export function Profile() {
  const { session, loading } = useSession();

  if (loading) return <div>Yükleniyor...</div>;
  if (!session) return <div>Giriş yapılmamış</div>;

  return <div>Hoşgeldin, {session.email}</div>;
}
```

## Giriş Yap

```typescript
'use client';

import { useLogin } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useLogin();

  async function handleSubmit(e) {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);

    const response = await login({
      email: formData.get('email'),
      password: formData.get('password'),
    });

    if (response.session) {
      console.log('Giriş yapıldı!');
    } else if (response.error) {
      console.error('Hata:', response.error);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Şifre" required />
      <button disabled={isLoading}>
        {isLoading ? 'Yükleniyor...' : 'Giriş Yap'}
      </button>
    </form>
  );
}
```

## Çıkış Yap

```typescript
'use client';

import { useLogout } from 'nguard/client';

export function LogoutButton() {
  const { logout, isLoading } = useLogout();

  return (
    <button onClick={logout} disabled={isLoading}>
      {isLoading ? 'Yükleniyor...' : 'Çıkış Yap'}
    </button>
  );
}
```

## Oturumu Güncelle

```typescript
'use client';

import { useSessionUpdate } from 'nguard/client';

export function UpdateRole() {
  const { updateSession, isLoading } = useSessionUpdate();

  async function handleUpdate() {
    // API'den yeni oturum verisi al
    const response = await fetch('/api/user/update-role', {
      method: 'POST',
      body: JSON.stringify({ role: 'admin' }),
    });

    if (response.ok) {
      const data = await response.json();
      await updateSession(data.session);
    }
  }

  return (
    <button onClick={handleUpdate} disabled={isLoading}>
      Role'ü Güncelle
    </button>
  );
}
```

## Oturumu Doğrula

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

## Hata Yönetimi

Tüm login/logout metodları hata bilgisi ile yanıt döndürür:

```typescript
'use client';

import { useState } from 'react';
import { useLogin } from 'nguard/client';

export function SafeLoginForm() {
  const { login, isLoading } = useLogin();
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setMessage('');
    setError('');

    const fd = new FormData(e.currentTarget);

    try {
      const response = await login({
        email: fd.get('email'),
        password: fd.get('password'),
      });

      if (response.session) {
        setMessage('Giriş başarılı!');
      } else if (response.error) {
        setError(response.error);
      }
    } catch (err) {
      setError('Ağ hatası: ' + err.message);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      {message && <div style={{ color: 'green' }}>{message}</div>}
      {error && <div style={{ color: 'red' }}>{error}</div>}

      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Şifre" required />
      <button disabled={isLoading}>
        {isLoading ? 'Yükleniyor...' : 'Giriş Yap'}
      </button>
    </form>
  );
}
```

## Tüm Hooks

| Hook | Kullanım |
|------|----------|
| `useSession()` | Mevcut oturumu al |
| `useLogin()` | Kimlik bilgileri ile giriş yap |
| `useLogout()` | Kullanıcıyı çıkış yap |
| `useSessionUpdate()` | Oturum verisi güncelle |
| `useValidateSession()` | Oturum geçerli mi kontrol et |
| `useAuth()` | Daha fazla özellik ile hook |

## Sunucu Tarafı Fonksiyonlar

| Fonksiyon | Kullanım |
|-----------|----------|
| `auth()` | Server Components'te oturum al |
| `nguard.createSession()` | Yeni oturum oluştur |
| `nguard.clearSession()` | Oturumu temizle |
| `nguard.validateSession()` | Token doğrula |

## En İyi Uygulamalar

1. **Server Components'te oturum al** - Daha iyi performans ve SEO
2. **Yükleme durumlarını işle** - Yükleme göstergeleri göster
3. **Hataları zarif şekilde işle** - Giriş hatalarında çöküş yapma
4. **Yüklenişte doğrula** - Uygulama başladığında oturumu kontrol et
5. **TypeScript kullan** - Oturum verisi için tür güvenliği al

## Ayrıca Bak

- [CLI Kurulum](./CLI-SETUP.md) - Kurulum
- [API Referansı](./API-CLIENT.md) - Tüm metodlar
- [Ara Yazılım Rehberi](./MIDDLEWARE.md) - Güvenlik ekle
- [Doğrulama Rehberi](./VALIDATION.md) - Oturumu kontrol et
