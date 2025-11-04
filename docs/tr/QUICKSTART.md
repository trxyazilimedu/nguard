# Nguard - Hızlı Başlangıç (5 dakika)

Adım adım Nguard'ı kuralım!

## 1️⃣ Kurulum

```bash
npm install nguard
```

## 2️⃣ Environment Değişkenleri

`.env.local` dosyası oluştur:

```env
NGUARD_SECRET=your-secret-min-32-chars-openssl-rand-base64-32
BACKEND_API_URL=http://localhost:8080/api
```

Secret oluştur:
```bash
openssl rand -base64 32
```

> **Not**: `BACKEND_API_URL` kendi backend'inizin adresidir (Spring, Express, Node.js vb.)

## 3️⃣ Server Setup (lib/auth.ts)

```typescript
import { initializeServer } from 'nguard/server';
import { headers } from 'next/headers';

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET!,
  secure: process.env.NODE_ENV === 'production',
});

// Next Auth gibi auth() fonksiyonu - server ve client'te kullan
export async function auth() {
  try {
    const headersList = await headers();
    const cookie = headersList.get('cookie');
    if (!cookie) return null;

    return await nguard.validateSession(cookie);
  } catch (error) {
    return null;
  }
}

// Helper functions
export const createSession = (user: any, data?: any) =>
  nguard.createSession(user, data);

export const clearSession = () =>
  nguard.clearSession();
```

> **Kullanım**: `auth()` fonksiyonunu Next Auth gibi server component'lerde ve API route'larda kullan!

## 4️⃣ API Routes Oluştur

### Login Endpoint

```typescript
// app/api/auth/login/route.ts
import { nguard } from '@/lib/auth';

const BACKEND_API_URL = process.env.BACKEND_API_URL!;

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();

    // Step 1: Backend'e login isteği gönder
    const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!backendResponse.ok) {
      throw new Error('Authentication failed');
    }

    // Step 2: Backend'den verileri al
    const backendData = await backendResponse.json();

    // Step 3: Nguard ile session oluştur
    // Backend'den gelen tüm verileri olduğu gibi session'a geç
    const { session, setCookieHeader } = await nguard.createSession({
      ...backendData,     // Backend'den gelen tüm veriler (user, role, permissions, vb)
      expires: Date.now() + 24 * 60 * 60 * 1000  // İsteğe bağlı: expiration belirle
    });

    return Response.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    console.error('Login error:', error);
    return Response.json({ error: 'Login başarısız' }, { status: 401 });
  }
}
```

### Logout Endpoint

```typescript
// app/api/auth/logout/route.ts
import { nguard } from '@/lib/auth';

export async function POST(request: Request) {
  return Response.json({ ok: true }, {
    headers: { 'Set-Cookie': nguard.clearSession() }
  });
}
```

### Session Endpoint

```typescript
// app/api/auth/session/route.ts
import { nguard } from '@/lib/auth';

export async function GET(request: Request) {
  try {
    const headers = Object.fromEntries(request.headers.entries());
    const session = await nguard.validateSession(headers.cookie);

    if (!session) {
      return Response.json({ session: null }, { status: 401 });
    }

    return Response.json({ session });
  } catch (error) {
    return Response.json({ session: null }, { status: 401 });
  }
}
```

## 5️⃣ Client Setup (app/layout.tsx)

### Basit Kurulum (Önerilen)

```typescript
'use client';

import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }: any) {
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

**Otomatik olarak kullanılan varsayılan API endpoints:**
- Login: `POST /api/auth/login`
- Logout: `POST /api/auth/logout`

### Custom Callbacks İle (İsteğe Bağlı)

Eğer farklı endpoint'ler kullanmak istersen:

```typescript
'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback = async (credentials) => {
  const res = await fetch('/auth/login', { // Farklı endpoint
    method: 'POST',
    body: JSON.stringify(credentials),
  });
  const data = await res.json();
  return { user: data.user, data: data.data };
};

export default function RootLayout({ children }: any) {
  return (
    <html>
      <body>
        <SessionProvider onLogin={handleLogin}>
          {children}
        </SessionProvider>
      </body>
    </html>
  );
}
```

## 6️⃣ Server Component'te Session'ı Al

```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  // Next Auth gibi - server component'te doğrudan session al
  const session = await auth();

  if (!session) {
    return <div>Lütfen giriş yapın</div>;
  }

  return (
    <div>
      <h1>Hoşgeldiniz, {session.user.name}</h1>
      <p>Email: {session.user.email}</p>
      <p>Role: {session.data?.role}</p>
    </div>
  );
}
```

## 7️⃣ Client Component'te Kullan

### Basit Kullanım

```typescript
'use client';

import { useAuth } from 'nguard/client';

export function Dashboard() {
  const { user, isAuthenticated, logout } = useAuth();

  if (!isAuthenticated) return <LoginForm />;

  return (
    <div>
      <h1>Hoşgeldiniz, {user?.name}</h1>
      <button onClick={logout}>Çıkış Yap</button>
    </div>
  );
}
```

### Hata Yönetimi İle

```typescript
'use client';

import { useAuth } from 'nguard/client';
import { useState } from 'react';

export function LoginForm() {
  const { login, isLoading } = useAuth();
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setMessage(null);
    setError(null);

    const data = new FormData(e.currentTarget);

    try {
      // login() API response'unu doğrudan döndürür
      const response = await login({
        email: data.get('email'),
        password: data.get('password'),
      });

      // API'niz response yapısını tanımlar
      console.log('API Response:', response);

      if (response.success) {
        setMessage(response.message || 'Giriş başarılı');
        // Dashboard'a yönlendir
      } else {
        setError(response.error || response.message || 'Giriş başarısız');
      }
    } catch (err) {
      // Network/fetch hatalarını işle
      setError(err instanceof Error ? err.message : 'Giriş başarısız');
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      {message && <div style={{ color: 'green' }}>{message}</div>}
      {error && <div style={{ color: 'red' }}>{error}</div>}

      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Şifre" required />
      <button disabled={isLoading}>
        {isLoading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
      </button>
    </form>
  );
}
```

## ✅ Tamamlandı!

Artık Nguard kuruldu ve çalışıyor. Akış:

1. Kullanıcı form doldurur
2. `login()` çağrılır
3. Client `onLogin` callback → `/api/auth/login` POST
4. Frontend API Route → **Backend'e isteği gönder**
5. Backend'de (Spring/Express/vb.) → kullanıcı doğrulama + veritabanı kontrolü
6. Backend'den user verisi döner
7. Frontend'te Nguard → JWT oluşturur ve cookie'ye koyar
8. Session state güncellenir
9. Component re-render olur → Giriş yapılmış ✅

**Fark**: Artık authentication backend'de yapılıyor, Nguard sadece JWT/session yönetiyor!

## 📖 Sonraki Adımlar

- [CALLBACKS.md](./CALLBACKS.md) - Callback'leri detaylı öğren
- [API-SERVER.md](./API-SERVER.md) - Server fonksiyonları
- [API-CLIENT.md](./API-CLIENT.md) - Client hooks
- [EXAMPLES.md](./EXAMPLES.md) - Gerçek örnekler
