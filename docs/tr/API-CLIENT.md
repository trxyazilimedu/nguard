# Client API - Referans

Client-side hooks ve component'leri detaylı olarak.

## SessionProvider

Uygulamanızı SessionProvider ile sarın (root layout).

```typescript
'use client';

import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }) {
  return (
    <SessionProvider
      cookieName="session"              // default: 'nguard-session'
      onLogin={handleLogin}             // Optional
      onLogout={handleLogout}           // Optional
      onInitialize={handleInitialize}   // Optional
      onSessionChange={handleChange}    // Optional
    >
      {children}
    </SessionProvider>
  );
}
```

**Props:**
- `children` (ReactNode) - App components
- `cookieName` (string) - Cookie adı
- `onLogin` (LoginCallback) - Login callback
- `onLogout` (LogoutCallback) - Logout callback
- `onInitialize` (InitializeSessionCallback) - Init callback
- `onSessionChange` (function) - Session değiştiğinde çalışır

---

## useAuth()

En çok kullanılan hook. Authentication bilgisi al.

```typescript
const {
  user,              // SessionUser | null
  isAuthenticated,   // boolean
  isLoading,         // boolean (login/logout sırasında true)
  login,             // <T>(credentials: T) => Promise<void>
  logout,            // () => Promise<void>
} = useAuth();
```

**Örnek:**
```typescript
'use client';

import { useAuth } from 'nguard/client';

export function Header() {
  const { user, isAuthenticated, logout } = useAuth();

  if (!isAuthenticated) {
    return <a href="/login">Login</a>;
  }

  return (
    <div>
      <span>Welcome, {user?.name}</span>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

## useSession()

Tam session bilgisine erişim. Diğer hooks'lar bunu kullanır.

```typescript
const {
  session,           // Session | null
  status,            // 'loading' | 'authenticated' | 'unauthenticated'
  login,             // <T>(creds: T) => Promise<void>
  logout,            // () => Promise<void>
  updateSession,     // (user, data?) => Promise<void>
  isLoading,         // boolean
} = useSession();
```

**Örnek:**
```typescript
'use client';

import { useSession } from 'nguard/client';

export function Profile() {
  const { session, status, updateSession } = useSession();

  if (status === 'loading') return <div>Loading...</div>;
  if (status === 'unauthenticated') return <div>Login required</div>;

  return (
    <div>
      <h1>{session?.user.name}</h1>
      <p>Role: {session?.data?.role}</p>
      <button onClick={() => updateSession(session!.user, { theme: 'dark' })}>
        Theme: Dark
      </button>
    </div>
  );
}
```

---

## useLogin()

Sadece login fonksiyonuna ihtiyacın varsa.

```typescript
const {
  login,      // <T>(credentials: T) => Promise<void>
  isLoading,  // boolean
} = useLogin();
```

**Örnek:**
```typescript
'use client';

import { useLogin } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useLogin();

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const data = new FormData(e.currentTarget);
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
```

---

## useLogout()

Sadece logout fonksiyonuna ihtiyacın varsa.

```typescript
const {
  logout,     // () => Promise<void>
  isLoading,  // boolean
} = useLogout();
```

**Örnek:**
```typescript
'use client';

import { useLogout } from 'nguard/client';

export function LogoutButton() {
  const { logout, isLoading } = useLogout();

  return (
    <button onClick={logout} disabled={isLoading}>
      {isLoading ? 'Çıkış yapılıyor...' : 'Çıkış Yap'}
    </button>
  );
}
```

---

## useSessionUpdate()

Session'ı güncelle.

```typescript
const {
  updateSession,  // (user: SessionUser, data?: SessionData) => Promise<void>
  isLoading,      // boolean
} = useSessionUpdate();
```

**Örnek:**
```typescript
'use client';

import { useSessionUpdate, useAuth } from 'nguard/client';

export function Settings() {
  const { user } = useAuth();
  const { updateSession, isLoading } = useSessionUpdate();

  return (
    <div>
      <button onClick={async () => {
        await updateSession(
          user!,
          { theme: 'dark', language: 'tr' }
        );
      }} disabled={isLoading}>
        Ayarları Kaydet
      </button>
    </div>
  );
}
```

---

## Client Callback Types

### LoginCallback

Login sırasında çalışır. Frontend'den backend'e credentials gönder.

```typescript
import { type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback<{ email: string; password: string }> = async (credentials) => {
  // 1. Backend'e istek gönder
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });

  if (!res.ok) throw new Error('Login başarısız');

  // 2. Response'tan user + data al
  const data = await res.json();

  // 3. { user, data, token } döndür
  return {
    user: data.session.user,
    data: data.session.data,
    token: data.session.token, // Optional
  };
};
```

**Dönüş Değeri:**
```typescript
{
  user: SessionUser,           // Zorunlu
  data?: SessionData,          // Optional
  token?: string,              // Optional
}
```

---

### LogoutCallback

Logout sırasında çalışır. Backend'i bilgilendir.

```typescript
import { type LogoutCallback } from 'nguard/client';

const handleLogout: LogoutCallback = async () => {
  // Backend'e logout isteği gönder
  await fetch('/api/auth/logout', { method: 'POST' });

  // Diğer cleanup işlemleri
  // localStorage temizle, etc.
};
```

---

### InitializeSessionCallback

App açıldığında çalışır. Saved session'ı yükle.

```typescript
import { type InitializeSessionCallback } from 'nguard/client';

const handleInitialize: InitializeSessionCallback = async () => {
  try {
    // Backend'den current session'ı al
    const res = await fetch('/api/auth/session');

    if (res.ok) {
      const data = await res.json();
      return data.session; // Session | null
    }
  } catch (error) {
    console.error('Session load error:', error);
  }

  return null; // No session
};
```

**Dönüş Değeri:**
```typescript
Session | null    // null ise unauthenticated
```

---

## Setup Örnekleri

### Basic Setup
```typescript
'use client';

import { SessionProvider, type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback = async (creds) => {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(creds),
  });
  return await res.json();
};

export default function RootLayout({ children }) {
  return (
    <SessionProvider onLogin={handleLogin}>
      {children}
    </SessionProvider>
  );
}
```

### Full Setup (All Callbacks)
```typescript
'use client';

import { SessionProvider, type LoginCallback, type LogoutCallback, type InitializeSessionCallback } from 'nguard/client';

const handleLogin: LoginCallback = async (creds) => {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(creds),
  });
  if (!res.ok) throw new Error('Login başarısız');
  return await res.json();
};

const handleLogout: LogoutCallback = async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
};

const handleInitialize: InitializeSessionCallback = async () => {
  const res = await fetch('/api/auth/session');
  if (res.ok) {
    const data = await res.json();
    return data.session;
  }
  return null;
};

export default function RootLayout({ children }) {
  return (
    <SessionProvider
      onLogin={handleLogin}
      onLogout={handleLogout}
      onInitialize={handleInitialize}
      onSessionChange={(session) => {
        console.log('Session changed:', session?.user.email);
      }}
    >
      {children}
    </SessionProvider>
  );
}
```

---

## Hook Combinations

### Login Form
```typescript
'use client';

import { useLogin } from 'nguard/client';

export function LoginForm() {
  const { login, isLoading } = useLogin();

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const data = new FormData(e.currentTarget);
      try {
        await login({
          email: data.get('email'),
          password: data.get('password'),
        });
      } catch (error) {
        alert(error instanceof Error ? error.message : 'Login başarısız');
      }
    }}>
      {/* Form inputs */}
    </form>
  );
}
```

### Protected Component
```typescript
'use client';

import { useAuth } from 'nguard/client';

export function AdminPanel() {
  const { isAuthenticated, user } = useAuth();

  if (!isAuthenticated) {
    return <div>Giriş yapılmalı</div>;
  }

  if (user?.role !== 'admin') {
    return <div>Yetkisiz erişim</div>;
  }

  return <div>Admin Paneli</div>;
}
```

### Settings Page
```typescript
'use client';

import { useSession, useSessionUpdate } from 'nguard/client';

export function SettingsPage() {
  const { session } = useSession();
  const { updateSession, isLoading } = useSessionUpdate();

  return (
    <button onClick={async () => {
      await updateSession(session!.user, {
        ...session!.data,
        theme: 'dark',
      });
    }} disabled={isLoading}>
      Theme: Dark
    </button>
  );
}
```

---

## 🔗 İlgili Sayfalar

- [API-SERVER.md](./API-SERVER.md) - Server API
- [CALLBACKS.md](./CALLBACKS.md) - Callback'ler detaylı
- [EXAMPLES.md](./EXAMPLES.md) - Gerçek örnekler
