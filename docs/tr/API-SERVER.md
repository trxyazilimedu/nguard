# Server API - Referans

Server tarafı fonksiyonları ve callback'leri detaylı olarak.

## initializeServer()

Nguard sunucusunu başlat.

```typescript
import { initializeServer } from 'nguard/server';

const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET!,          // ✅ Zorunlu
  cookieName: 'session',                       // 'nguard-session' (default)
  secure: process.env.NODE_ENV === 'production', // true (default)
  sameSite: 'Lax',                             // 'Lax' (default)
  maxAge: 24 * 60 * 60,                        // 24 hours (default)
});
```

**Parametreler:**
- `secret` (string) - Minimum 32 karakter, güvenli key
- `cookieName` (string) - Cookie adı
- `secure` (boolean) - HTTPS-only cookie
- `sameSite` (string) - CSRF koruması ('Strict', 'Lax', 'None')
- `maxAge` (number) - Session süresi (saniye)

---

## createSession()

Yeni session oluştur (JWT + Cookie).

```typescript
const { session, token, setCookieHeader } = await nguard.createSession(
  user,           // SessionUser { id, email?, name?, ... }
  data,           // SessionData { role, permissions, ... } (optional)
  options         // { maxAge?, secure?, sameSite? } (optional)
);
```

**Dönüş Değeri:**
```typescript
{
  session: Session,              // { user, expires, data }
  token: string,                 // JWT token
  setCookieHeader: string        // Set-Cookie header
}
```

**Örnek:**
```typescript
const { session, setCookieHeader } = await nguard.createSession(
  { id: '123', email: 'user@example.com', name: 'John' },
  { role: 'admin', permissions: ['read', 'write'] }
);

// Response'u döndür
Response.json({ session }, {
  headers: { 'Set-Cookie': setCookieHeader }
});
```

---

## validateSession()

Mevcut session'ı doğrula.

```typescript
const session = await nguard.validateSession(
  cookieString,    // Cookie header string (optional)
  cookieValue      // Direkt cookie değeri (optional)
);
```

**Dönüş Değeri:**
```typescript
Session | null    // null ise geçersiz/expired session
```

**Örnek:**
```typescript
// GET endpoint'te
export async function GET(request: Request) {
  const headers = Object.fromEntries(request.headers.entries());
  const session = await nguard.validateSession(headers.cookie);

  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  return Response.json({ session });
}
```

---

## clearSession()

Session'ı sil (logout).

```typescript
const clearCookieHeader = nguard.clearSession();

// Response'ta Set-Cookie header'ı olarak gönder
Response.json({ ok: true }, {
  headers: { 'Set-Cookie': clearCookieHeader }
});
```

---

## getSessionFromRequest()

Request'ten session'ı al.

```typescript
const session = await nguard.getSessionFromRequest(
  headers,    // request.headers (optional)
  cookies     // { cookieName: value } (optional)
);
```

**Örnek:**
```typescript
export async function GET(request: Request) {
  const headers = Object.fromEntries(request.headers.entries());
  const session = await nguard.getSessionFromRequest(headers);
  // ...
}
```

---

## updateSession()

Session'ı güncelle (yeni user/data ile yeni token oluştur).

```typescript
const { session, setCookieHeader } = await nguard.updateSession(
  user,      // Yeni/güncellenmiş user
  data,      // Yeni/güncellenmiş data (optional)
  options    // Session options (optional)
);
```

**Örnek:**
```typescript
const { session, setCookieHeader } = await nguard.updateSession(
  { ...currentUser, name: 'New Name' },
  { role: 'moderator' }
);
```

---

## Callback'ler (Server-Side)

### onServerLogin()

Kullanıcı giriş yaparken çalışır. Authentication logic'ini buraya yaz.

```typescript
import { type ServerLoginCallback } from 'nguard/server';

const handleServerLogin: ServerLoginCallback<{
  email: string;
  password: string;
}> = async (credentials) => {
  // 1. Veritabanından kullanıcıyı bul
  const user = await db.user.findUnique({
    where: { email: credentials.email }
  });

  // 2. Kullanıcı yoksa hata
  if (!user) throw new Error('Kullanıcı bulunamadı');

  // 3. Şifreyi doğrula
  const isValid = await bcrypt.compare(credentials.password, user.passwordHash);
  if (!isValid) throw new Error('Geçersiz şifre');

  // 4. User ve data döndür
  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    data: {
      role: user.role,
      permissions: await getPermissions(user.id),
    }
  };
};

nguard.onServerLogin(handleServerLogin);
```

**Dikkat:**
- Server-side validation yapılır
- Hata fırlatırsa login başarısız olur
- Client-side hiçbir şeye güvenme

---

### onServerLogout()

Logout olduğunda çalışır. Cleanup işlemlerini buraya yaz.

```typescript
import { type ServerLogoutCallback } from 'nguard/server';

const handleServerLogout: ServerLogoutCallback = async (user) => {
  // 1. Refresh token'ları invalidate et
  await db.refreshToken.deleteMany({
    where: { userId: user.id }
  });

  // 2. Audit log tutuş
  await db.auditLog.create({
    userId: user.id,
    action: 'LOGOUT',
    timestamp: new Date(),
  });

  // 3. Diğer session'ları temizle
  await invalidateOtherSessions(user.id);
};

nguard.onServerLogout(handleServerLogout);
```

---

### onValidateSession()

Her session doğrulanırken çalışır. Extra validation yapabilirsin.

```typescript
import { type ValidateSessionCallback } from 'nguard/server';

const handleValidateSession: ValidateSessionCallback = async (session) => {
  // 1. Kullanıcı hala aktif mi?
  const user = await db.user.findUnique({
    where: { id: session.user.id }
  });

  if (!user || !user.isActive) {
    return false; // Session geçersiz
  }

  // 2. Permission'lar revoke edildi mi?
  const hasPermission = await checkPermissions(user.id);
  if (!hasPermission) {
    return false;
  }

  return true; // Session geçerli
};

nguard.onValidateSession(handleValidateSession);
```

---

### onJWT()

JWT payload'ı transform et (opsiyonel).

```typescript
nguard.onJWT(async (token) => {
  // Token'a custom claim'ler ekle
  return {
    ...token,
    scope: 'admin',
    customClaim: 'value'
  };
});
```

---

### onSession()

Session object'ini transform et (opsiyonel).

```typescript
nguard.onSession(async (session) => {
  // Session'a computed properties ekle
  return {
    ...session,
    lastActive: new Date(),
    isAdmin: session.data?.role === 'admin'
  };
});
```

---

## Type Definitions

### SessionUser
```typescript
interface SessionUser {
  id: string;           // ✅ Zorunlu
  email?: string;
  name?: string;
  [key: string]: any;   // Custom properties
}
```

### Session
```typescript
interface Session {
  user: SessionUser;
  expires: number;      // Milliseconds
  data?: SessionData;
}
```

### SessionData
```typescript
type SessionData = {
  [key: string]: any;   // Herhangi bir veri
};
```

---

## Örnekler

### Database ile Login
```typescript
const handleServerLogin: ServerLoginCallback = async (creds) => {
  const user = await db.user.findUnique({
    where: { email: creds.email }
  });

  if (!user || !await bcrypt.compare(creds.password, user.passwordHash)) {
    throw new Error('Invalid credentials');
  }

  return {
    user: { id: user.id, email: user.email, name: user.name },
    data: { role: user.role }
  };
};

nguard.onServerLogin(handleServerLogin);
```

### Rate Limiting
```typescript
const loginAttempts = new Map<string, number>();

const handleServerLogin: ServerLoginCallback = async (creds) => {
  const attempts = loginAttempts.get(creds.email) || 0;

  if (attempts > 5) {
    throw new Error('Too many attempts, try later');
  }

  try {
    const user = await authenticateUser(creds);
    loginAttempts.delete(creds.email);
    return { user };
  } catch (error) {
    loginAttempts.set(creds.email, attempts + 1);
    throw error;
  }
};
```

### Permission Based Validation
```typescript
const handleValidateSession: ValidateSessionCallback = async (session) => {
  const permissions = await db.permission.findMany({
    where: { userId: session.user.id }
  });

  if (permissions.length === 0) {
    return false; // No permissions
  }

  return true;
};
```

---

## 🔗 İlgili Sayfalar

- [API-CLIENT.md](./API-CLIENT.md) - Client hooks
- [CALLBACKS.md](./CALLBACKS.md) - Callback'ler detaylı
- [EXAMPLES.md](./EXAMPLES.md) - Gerçek örnekler
