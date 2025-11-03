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

    // Step 2: Backend'den kullanıcı verisini al
    const backendData = await backendResponse.json();
    const { user } = backendData;

    // Step 3: Nguard ile session oluştur
    const { session, setCookieHeader } = await nguard.createSession(
      user, // { id, email, name }
      { role: user.role } // Backend'den gelen data
    );

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

```typescript
'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

// Callback: Frontend'den login isteği gönder
const handleLogin: LoginCallback = async (credentials) => {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });

  if (!res.ok) throw new Error('Login başarısız');
  const data = await res.json();
  return { user: data.session.user, data: data.session.data };
};

// Callback: Logout işlemi
const handleLogout = async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
};

export default function RootLayout({ children }: any) {
  return (
    <html>
      <body>
        <SessionProvider
          onLogin={handleLogin}
          onLogout={handleLogout}
        >
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

```typescript
'use client';

import { useAuth } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useAuth();

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const data = new FormData(e.currentTarget);

      // login() → client onLogin callback → POST /api/auth/login → onServerLogin callback
      await login({
        email: data.get('email'),
        password: data.get('password'),
      });
    }}>
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Şifre" required />
      <button disabled={isLoading}>
        {isLoading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
      </button>
    </form>
  );
}

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
