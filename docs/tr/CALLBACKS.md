# Callback'ler - Rehber

Nguard'ın kalbı callback'lerdir. Serverda ve clientda authentication logic'ini buraya yazarsın.

## 🎯 Callback Sistemi Nasıl Çalışır?

```
User Clicks Login
    ↓
useAuth().login(credentials)
    ↓
SessionProvider.login() çalışır
    ↓
Client onLogin Callback (senin kodon!)
    ↓
    └─ fetch('/api/auth/login', { body: credentials })
    │
    └─→ POST /api/auth/login handler
        │
        └─ Server onServerLogin Callback (senin kodon!)
           │
           ├─ DB'den kullanıcı bul
           ├─ Şifreyi doğrula
           └─ { user, data } döndür
        │
        └─→ NguardServer.createSession()
           │
           ├─ JWT token oluştur
           └─ Set-Cookie header
    │
    └─← Response { session }
    │
    └─ SessionProvider state update
       │
       └─ useAuth().isAuthenticated = true
           │
           └─ Components re-render ✅
```

---

## 📍 Server-Side Callbacks (lib/auth.ts)

### 1. onServerLogin()

**Amaç:** Backend'den dönen user verisini session'a dönüştür

**Ne zaman çalışır:** User login yapıldığında (frontend API route'da)

**Örnek:**
```typescript
import { type ServerLoginCallback } from 'nguard/server';

const handleServerLogin: ServerLoginCallback<{
  email: string;
  password: string;
}> = async (credentials) => {
  // NOT: Authentication backend'de yapılacak!
  // Bu callback sadece user verisini session'a dönüştürmek için kullanılır

  // Backend'e login isteği gönder (frontend API route'da yapılır)
  // Örnek: app/api/auth/login/route.ts
  //   const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {...})
  //   const backendData = await backendResponse.json()
  //   const { session } = await nguard.createSession(backendData.user, ...)

  throw new Error('This callback should not be directly used');
};

// Normalde bu callback'i override etmezsin!
// Frontend API route'larda authentication yapılıyor
```

**Örnek (Frontend API Route):**
```typescript
// app/api/auth/login/route.ts
import { nguard } from '@/lib/auth';

const BACKEND_API_URL = process.env.BACKEND_API_URL!;

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();

    // 1. Backend'e authentication isteği gönder
    const backendResponse = await fetch(`${BACKEND_API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!backendResponse.ok) {
      throw new Error('Authentication failed');
    }

    // 2. Backend'den user verisini al
    const backendData = await backendResponse.json();
    const { user, role, permissions } = backendData;

    // 3. Session oluştur (Nguard)
    const { session, setCookieHeader } = await nguard.createSession(
      user, // { id, email, name }
      { role, permissions } // Custom data
    );

    return Response.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    return Response.json({ error: 'Login failed' }, { status: 401 });
  }
}
```

**Key Points:**
- ✅ Authentication backend'de yapılır
- ✅ Frontend proxy role olarak çalışır
- ✅ Nguard sadece session yönetir
- ✅ Database backend'de güvenli şekilde tutulur

---

### 2. onServerLogout()

**Amaç:** Logout sırasında backend cleanup işlemlerini tetikle

**Ne zaman çalışır:** User logout yaptığında (frontend API route'da)

**Örnek:**
```typescript
import { type ServerLogoutCallback } from 'nguard/server';

const handleServerLogout: ServerLogoutCallback = async (user) => {
  // NOT: Backend'e logout isteği gönder (frontend API route'da yapılır)
  // Örnek: app/api/auth/logout/route.ts
  //   await fetch(`${BACKEND_API_URL}/auth/logout`, {...})
  //   return clearCookie()

  // Nguard tarafında sadece cookie clear edilir
};

// Normalde bu callback'i override etmezsin!
```

**Örnek (Frontend API Route):**
```typescript
// app/api/auth/logout/route.ts
import { nguard } from '@/lib/auth';

const BACKEND_API_URL = process.env.BACKEND_API_URL!;

export async function POST(request: Request) {
  try {
    const headers = Object.fromEntries(request.headers.entries());
    const session = await nguard.validateSession(headers.cookie);

    if (session) {
      // 1. Backend'e logout isteği gönder (cleanup işlemleri için)
      await fetch(`${BACKEND_API_URL}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: session.user.id }),
      }).catch(err => console.error('Backend logout error:', err));
    }

    // 2. Frontend'te cookie'yi temizle
    return Response.json({ ok: true }, {
      headers: { 'Set-Cookie': nguard.clearSession() }
    });
  } catch (error) {
    return Response.json({ error: 'Logout failed' }, { status: 500 });
  }
}
```

**Key Points:**
- ✅ Token invalidation
- ✅ Cleanup işlemleri backend'de
- ✅ Audit logging
- ✅ Cache temizleme
- ✅ Frontend cookie temizleme

---

### 3. onValidateSession()

**Amaç:** Session doğrulaması (her request'te çalışır)

**Ne zaman çalışır:** Session'ı validate edilirken

**Örnek:**
```typescript
import { type ValidateSessionCallback } from 'nguard/server';

const handleValidateSession: ValidateSessionCallback = async (session) => {
  // NOT: Backend'e validation isteği gönder (frontend API route'da yapılır)
  // Örnek: app/api/auth/session/route.ts
  //   const session = await nguard.validateSession(headers.cookie);
  //   await fetch(`${BACKEND_API_URL}/auth/validate`, {...})
  //   if valid return session, else return null

  // Session JWT'de encoded olduğu için geçerliliği check edilir
  return true; // JWT valid ise bu çalışır
};

// Opsiyonel olarak override edebilirsin
```

**Örnek (Frontend API Route):**
```typescript
// app/api/auth/session/route.ts
import { nguard } from '@/lib/auth';

const BACKEND_API_URL = process.env.BACKEND_API_URL!;

export async function GET(request: Request) {
  try {
    const headers = Object.fromEntries(request.headers.entries());
    const session = await nguard.validateSession(headers.cookie);

    if (!session) {
      return Response.json({ session: null }, { status: 401 });
    }

    // 1. Backend'e session validation isteği gönder (opsiyonel)
    const validationResponse = await fetch(`${BACKEND_API_URL}/auth/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: session.user.id }),
    });

    if (!validationResponse.ok) {
      // User deactivated, permissions revoked, etc.
      return Response.json({ session: null }, { status: 401 });
    }

    // 2. Session valid, return it
    return Response.json({ session });
  } catch (error) {
    return Response.json({ session: null }, { status: 401 });
  }
}
```

**Key Points:**
- ✅ JWT geçerliliği Nguard'da check edilir
- ✅ Opsiyonel: Backend'de ek validation yapılabilir
- ✅ User aktifliği kontrol edilir
- ✅ Permission değişiklikleri detect edilir
- ✅ false dönerse session geçersiz

---

## 📍 Client-Side Callbacks (app/layout.tsx)

### 1. onLogin()

**Amaç:** Frontend'den backend'e credentials gönder

**Ne zaman çalışır:** useAuth().login() çağrıldığında

**Örnek:**
```typescript
import { type LoginCallback } from 'nguard/client';

const handleLogin: LoginCallback<{
  email: string;
  password: string;
}> = async (credentials) => {
  try {
    // 1. Backend'e POST isteği
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
      credentials: 'include', // CORS için
    });

    // 2. Response'ı kontrol et
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Login başarısız');
    }

    // 3. Session data'sını al
    const data = await response.json();

    // 4. { user, data, token } döndür
    return {
      user: data.session.user,
      data: data.session.data,
      token: data.session.token, // Optional
    };
  } catch (error) {
    // Hata fırlatırsan login başarısız
    throw error;
  }
};
```

**Key Points:**
- ✅ Backend'e istek gönder
- ✅ Response'ı handle et
- ✅ { user, data } döndür
- ❌ Hata fırlatırsan login başarısız

---

### 2. onLogout()

**Amaç:** Backend'i logout hakkında bilgilendir

**Ne zaman çalışır:** useAuth().logout() çağrıldığında

**Örnek:**
```typescript
import { type LogoutCallback } from 'nguard/client';

const handleLogout: LogoutCallback = async () => {
  try {
    // 1. Backend'e logout isteği
    const response = await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error('Logout başarısız');
    }

    // 2. LocalStorage temizle (opsiyonel)
    localStorage.removeItem('preferences');

    // 3. Analytics gönder (opsiyonel)
    gtag('event', 'logout', {
      user_id: currentUserId
    });

  } catch (error) {
    console.error('Logout error:', error);
    throw error;
  }
};
```

**Key Points:**
- ✅ Backend'i bilgilendir
- ✅ Local cleanup
- ✅ Analytics/tracking

---

### 3. onInitialize()

**Amaç:** App açılırken saved session'ı yükle

**Ne zaman çalışır:** SessionProvider mount olduğunda (page reload)

**Örnek:**
```typescript
import { type InitializeSessionCallback } from 'nguard/client';

const handleInitialize: InitializeSessionCallback = async () => {
  try {
    // 1. Backend'den current session'ı al
    const response = await fetch('/api/auth/session', {
      method: 'GET',
      credentials: 'include',
    });

    // 2. 401 = unauthorized = no session
    if (response.status === 401) {
      return null;
    }

    if (!response.ok) {
      throw new Error('Session load başarısız');
    }

    // 3. Session döndür
    const data = await response.json();
    return data.session; // Session | null

  } catch (error) {
    console.error('Initialize error:', error);
    return null; // No session
  }
};
```

**Key Points:**
- ✅ Backend'den session yükle
- ✅ null döndür = unauthenticated
- ✅ Session | null

---

## 🔄 Callback Akışı

### Login Flow
```
1. LoginForm → useAuth().login(creds)
   ↓
2. SessionProvider.login() → onLogin callback
   ↓
3. onLogin: fetch('/api/auth/login')
   ↓
4. Server: handleLogin → onServerLogin callback
   ↓
5. onServerLogin: DB kontrol → user bulma
   ↓
6. Response: { user, data }
   ↓
7. SessionProvider: state update → isAuthenticated = true
   ↓
8. Components: re-render ✅
```

### Logout Flow
```
1. LogoutButton → useAuth().logout()
   ↓
2. SessionProvider.logout() → onLogout callback
   ↓
3. onLogout: fetch('/api/auth/logout')
   ↓
4. Server: handleLogout → onServerLogout callback
   ↓
5. onServerLogout: cleanup (token delete, audit log)
   ↓
6. Response: Set-Cookie (clear)
   ↓
7. SessionProvider: state update → isAuthenticated = false
   ↓
8. Components: re-render ✅
```

### Initialize Flow
```
1. Page Load/Reload
   ↓
2. SessionProvider mount → onInitialize callback
   ↓
3. onInitialize: fetch('/api/auth/session')
   ↓
4. Server: validateSession() → onValidateSession callback
   ↓
5. onValidateSession: user check → true/false
   ↓
6. Response: { session } or null
   ↓
7. SessionProvider: state update
   ↓
8. useAuth().isAuthenticated = true/false
```

---

## 💡 Best Practices

### 1. Server-Side Validation
```typescript
// ✅ GOOD
const handleServerLogin = async (creds) => {
  const user = await db.user.findUnique({ where: { email: creds.email } });
  if (!user || !verifyPassword(creds.password)) {
    throw new Error('Invalid');
  }
  return { user };
};

// ❌ BAD - İtememe client-side data'ya
const handleServerLogin = async (creds) => {
  return { user: creds.user }; // No validation!
};
```

### 2. Error Handling
```typescript
// ✅ GOOD
const handleLogin = async (creds) => {
  try {
    const res = await fetch('/api/auth/login', { /* ... */ });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.message);
    }
    return await res.json();
  } catch (error) {
    throw error; // Re-throw
  }
};

// ❌ BAD - Error'ı swallow etme
const handleLogin = async (creds) => {
  try {
    return await fetch('/api/auth/login').then(r => r.json());
  } catch (error) {
    // Silent fail
    return null;
  }
};
```

### 3. Security
```typescript
// ✅ GOOD - Rate limiting
const attempts = new Map<string, number>();

const handleServerLogin = async (creds) => {
  const count = attempts.get(creds.email) || 0;
  if (count > 5) throw new Error('Too many attempts');

  try {
    const user = await authenticate(creds);
    attempts.delete(creds.email);
    return { user };
  } catch (error) {
    attempts.set(creds.email, count + 1);
    throw error;
  }
};

// ✅ GOOD - Password hashing
import bcrypt from 'bcrypt';

const isValid = await bcrypt.compare(
  credentials.password,
  user.passwordHash // Never store plain password!
);
```

---

## 🔗 İlgili Sayfalar

- [API-SERVER.md](./API-SERVER.md) - Server API
- [API-CLIENT.md](./API-CLIENT.md) - Client API
- [EXAMPLES.md](./EXAMPLES.md) - Gerçek örnekler
