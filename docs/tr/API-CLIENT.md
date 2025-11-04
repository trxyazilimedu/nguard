# Client API Referansı

Nguard'da client-side hooks ve component'lerin kapsamlı dokümantasyonu.

## Genel Bakış

Nguard, authentication yönetimi için React hooks sağlar. Authentication fonksiyonları API response'unu doğrudan döndürür. Backend'in response yapısını tanımlamasına izin verir.

## Response Tipleri

### login() - API Response

`login()` fonksiyonu `/api/auth/login` endpoint'inizden dönen response'u doğrudan geri verir.

**Örnek API Response:**

```typescript
const response = await login({ email, password });

// Response yapısı backend API'nizin tanımladığına bağlıdır
// Örnek:
{
  success: true,
  message: "Giriş başarılı",
  user: { id: 1, email: "user@example.com", name: "John" },
  data: { role: 'admin', permissions: ['read', 'write'] }
}
```

### logout() - API Response

`logout()` fonksiyonu `/api/auth/logout` endpoint'inizden dönen response'u doğrudan geri verir.

**Örnek API Response:**

```typescript
const response = await logout();

// Response yapısı backend API'nizin tanımladığına bağlıdır
// Örnek:
{
  success: true,
  message: "Çıkış başarılı"
}
```

### updateSession() - Lokal Response

`updateSession()` fonksiyonu lokal session state'i günceller ve güncellenmiş session'ı döndürür.

**Response:**

```typescript
const response = await updateSession(updatedUser, updatedData);

// Her zaman success ile güncellenmiş session döndürür
{
  success: true,
  message: "Session başarıyla güncellendi",
  session: {
    user: SessionUser,
    expires: number,
    data?: SessionData
  }
}
```

## Hata Yönetimi

API çağrısı başarısız olursa (network hatası, 4xx/5xx response), hata fırlatılır ve yakalanmalıdır:

```typescript
try {
  const response = await login({ email, password });
  // API'den gelen response'u işle
} catch (error) {
  // Network/fetch hatalarını işle
  console.error('Giriş başarısız:', error.message);
}
```

---

## Hooks

### useAuth()

Yaygın işlemler için basitleştirilmiş authentication hook.

**Döndürür:**

```typescript
{
  user: SessionUser | null;           // Geçerli kullanıcı veya null
  isAuthenticated: boolean;            // Kullanıcı giriş yaptıysa true
  isLoading: boolean;                  // Auth yüklünüyorsa true
  login: (credentials: any) => Promise<any>;  // API response döndürür
  logout: () => Promise<any>;                 // API response döndürür
}
```

**Örnek:**

```typescript
'use client';

import { useAuth } from 'nguard/client';

export function MyComponent() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();

  if (isLoading) return <div>Yükleniyor...</div>;

  if (!isAuthenticated) {
    return (
      <button onClick={() => login({ email: 'user@example.com', password: 'pass' })}>
        Giriş Yap
      </button>
    );
  }

  return (
    <div>
      <p>Merhaba, {user?.name}</p>
      <button onClick={logout}>Çıkış Yap</button>
    </div>
  );
}
```

---

### useSession()

Tam session context hook. Daha fazla kontrol istediğinde kullan.

**Döndürür:**

```typescript
{
  session: Session | null;                                    // Tam session objesi
  status: 'loading' | 'authenticated' | 'unauthenticated';   // Auth durumu
  login: <T = any>(credentials: T) => Promise<any>;           // API response döndürür
  logout: () => Promise<any>;                                 // API response döndürür
  updateSession: (user: SessionUser, data?: SessionData) => Promise<any>;  // Güncellenmiş session döndürür
  isLoading: boolean;                                         // İşlem yapılıyorsa true
}
```

---

### useLogin()

Sadece login fonksiyonu (basitleştirilmiş).

**Döndürür:**

```typescript
{
  login: <T = any>(credentials: T) => Promise<any>;  // API response döndürür
  isLoading: boolean;
}
```

---

### useLogout()

Sadece logout fonksiyonu (basitleştirilmiş).

**Döndürür:**

```typescript
{
  logout: () => Promise<any>;  // API response döndürür
  isLoading: boolean;
}
```

---

### useSessionUpdate()

Session verisini güncelle (role, tercihler, vb.).

**Döndürür:**

```typescript
{
  updateSession: (user: SessionUser, data?: SessionData) => Promise<any>;
  isLoading: boolean;
}
```

---

## Component'ler

### SessionProvider

App'ini sarılı tutar ve authentication context sağlar.

**Props:**

```typescript
interface SessionProviderProps {
  children?: ReactNode;
  cookieName?: string;                    // Varsayılan: 'nguard-session'
  onLogin?: LoginCallback;                // Custom login callback (isteğe bağlı)
  onLogout?: LogoutCallback;              // Custom logout callback (isteğe bağlı)
  onInitialize?: InitializeSessionCallback; // Custom init callback (isteğe bağlı)
  onSessionChange?: (session: Session | null) => void; // Session değiştiğinde çağrılır
}
```

**Varsayılan Davranış:**

Callback sağlamadığında, SessionProvider şu varsayılanları kullanır:
- `onLogin` → POST `/api/auth/login`
- `onLogout` → POST `/api/auth/logout`

**Örnek:**

```typescript
// app/layout.tsx
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

---

## Best Practices

### 1. Her Zaman Try-Catch Kullan

API çağrıları hata fırlatabilir:

```typescript
try {
  const response = await login(credentials);
  // Response'u işle
} catch (error) {
  // Hata mesajını göster
}
```

### 2. Backend Response'unu Tanımla

Backend'iniz response'un yapısını tanımlar. Frontend onu olduğu gibi döndürür:

```typescript
// Express.js örneği
app.post('/api/auth/login', (req, res) => {
  // Doğrulama yap...
  res.json({
    success: true,
    user: { id, email, name },
    token: jwtToken,
    custom_field: 'your data'
  });
});

// Frontend bu response'u olduğu gibi döndürür
const response = await login(credentials);
console.log(response.custom_field); // 'your data'
```

### 3. Loading State'i Kontrol Et

`isLoading` flag'ini kullan:

```typescript
<button disabled={isLoading}>
  {isLoading ? 'İşleniyor...' : 'Gönder'}
</button>
```

---

## Sonraki Adımlar

- [QUICKSTART.md](./QUICKSTART.md) - Kurulum rehberi
- [SESSION-UPDATE.md](./SESSION-UPDATE.md) - Session verisini güncelle
- [EXAMPLES.md](./EXAMPLES.md) - Gerçek dünya örnekleri
