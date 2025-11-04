# API Referansı

Tüm Nguard hook'ları ve sunucu fonksiyonları için tam referans.

## Client Hook'ları

### useSession()

Mevcut oturumu al.

**Döndürür:**
```typescript
{
  session: Session | null;
  loading: boolean;
}
```

**Örnek:**
```typescript
const { session, loading } = useSession();

if (loading) return <div>Yükleniyor...</div>;
return <div>{session?.email}</div>;
```

---

### useLogin()

Email ve şifre ile giriş yap.

**Döndürür:**
```typescript
{
  login: (credentials: { email: string; password: string }) => Promise<any>;
  isLoading: boolean;
}
```

**Örnek:**
```typescript
const { login, isLoading } = useLogin();

const response = await login({ email, password });
if (response.session) {
  // Başarılı
} else if (response.error) {
  // Hata
}
```

---

### useLogout()

Mevcut kullanıcıyı çıkış yap.

**Döndürür:**
```typescript
{
  logout: () => Promise<void>;
  isLoading: boolean;
}
```

**Örnek:**
```typescript
const { logout, isLoading } = useLogout();

await logout();
// Kullanıcı çıkış yapıldı
```

---

### useSessionUpdate()

Yeniden giriş yapmadan oturum verisi güncelle.

**Döndürür:**
```typescript
{
  updateSession: (sessionData: any) => Promise<void>;
  isLoading: boolean;
}
```

**Örnek:**
```typescript
const { updateSession, isLoading } = useSessionUpdate();

const newSession = { ...session, role: 'admin' };
await updateSession(newSession);
```

---

### useValidateSession()

Mevcut oturumun geçerli olup olmadığını kontrol et.

**Döndürür:**
```typescript
{
  validate: () => Promise<void>;
  isValid: boolean;
  validationResult: {
    valid: boolean;
    session?: any;
    expiresIn?: number;
    error?: string;
  } | null;
  isValidating: boolean;
}
```

**Örnek:**
```typescript
const { validate, isValid, validationResult } = useValidateSession();

await validate();

if (isValid) {
  console.log('Oturum geçerli');
  console.log('Süresi bitmesi:', validationResult?.expiresIn);
} else {
  console.log('Hata:', validationResult?.error);
}
```

---

### useAuth()

Daha fazla özellik ile alternatif hook.

**Döndürür:**
```typescript
{
  session: Session | null;
  isAuthenticated: boolean;
  login: (credentials: any) => Promise<any>;
  logout: () => Promise<void>;
  isLoading: boolean;
}
```

**Örnek:**
```typescript
const { session, isAuthenticated, login, logout, isLoading } = useAuth();

if (!isAuthenticated) {
  return <LoginForm onLogin={login} />;
}

return (
  <div>
    <p>{session?.email}</p>
    <button onClick={logout}>Çıkış</button>
  </div>
);
```

---

## Bileşenler

### SessionProvider

Tüm alt bileşenlere oturum durumunu sağlar.

**Props:**
```typescript
{
  children?: ReactNode;
  onLogin?: LoginCallback; // İsteğe bağlı
  onLogout?: LogoutCallback; // İsteğe bağlı
}
```

**Örnek:**
```typescript
<SessionProvider>
  <App />
</SessionProvider>
```

**Özel callback'ler ile:**
```typescript
<SessionProvider
  onLogin={async (credentials) => {
    const res = await fetch('/custom/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    return res.json();
  }}
  onLogout={async () => {
    await fetch('/custom/logout', { method: 'POST' });
  }}
>
  <App />
</SessionProvider>
```

---

## Sunucu Fonksiyonları

### auth()

Server Components'te mevcut oturumu al.

**Döndürür:**
```typescript
Promise<Session | null>
```

**Örnek:**
```typescript
import { auth } from '@/lib/auth';

export default async function Page() {
  const session = await auth();

  if (!session) {
    return <div>Kimlik doğrulanmamış</div>;
  }

  return <div>Merhaba {session.email}</div>;
}
```

---

### nguard.createSession()

Esnek oturum verisi ile yeni oturum oluştur.

**Parametreler:**
```typescript
createSession(sessionData: {
  [key: string]: any;
  expires: number;
}): Promise<{
  session: Session;
  setCookieHeader: string;
}>
```

**Örnek:**
```typescript
import { nguard } from '@/lib/auth';

const { session, setCookieHeader } = await nguard.createSession({
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  permissions: ['read', 'write'],
  expires: Date.now() + 24 * 60 * 60 * 1000,
});

// İstemciye Set-Cookie header ile döndür
return NextResponse.json({ session }, {
  headers: { 'Set-Cookie': setCookieHeader }
});
```

---

### nguard.clearSession()

Oturum cookie'sini temizle.

**Döndürür:**
```typescript
string // Cookie header'ı temizle
```

**Örnek:**
```typescript
import { nguard } from '@/lib/auth';

const cookieHeader = nguard.clearSession();

return NextResponse.json({ ok: true }, {
  headers: { 'Set-Cookie': cookieHeader }
});
```

---

### nguard.validateSession()

Bir cookie string'den oturum token'ını doğrula.

**Parametreler:**
```typescript
validateSession(cookieString: string): Promise<Session | null>
```

**Örnek:**
```typescript
import { nguard } from '@/lib/auth';

const session = await nguard.validateSession(cookieString);

if (!session) {
  return NextResponse.json({ error: 'Geçersiz oturum' }, { status: 401 });
}

// Oturum geçerli
return NextResponse.json({ session });
```

---

## Tipler

### Session

```typescript
interface Session {
  [key: string]: any;  // Backend'in sağladığı herhangi bir özellik
  expires: number;      // Millisaniye cinsinden sona erme zamanı
}
```

### LoginCallback

```typescript
type LoginCallback = (credentials: {
  email: string;
  password: string;
}) => Promise<any>;
```

### LogoutCallback

```typescript
type LogoutCallback = () => Promise<void>;
```

---

## Yanıt Desenleri

API yanıtlarınız herhangi bir yapıya sahip olabilir. Nguard bunları olduğu gibi döndürür:

### Giriş Başarısı
```typescript
{
  session: {
    id: 'user-123',
    email: 'user@example.com',
    role: 'admin'
  }
}
```

### Mesajlı Giriş
```typescript
{
  success: true,
  message: 'Başarıyla giriş yapıldı',
  session: { /* ... */ }
}
```

### Giriş Hatası
```typescript
{
  success: false,
  error: 'Geçersiz kimlik bilgileri'
}
```

---

## Hata Yönetimi

Tüm hook'lar hata bilgisi içeren yanıtlar döndürür:

```typescript
const { login } = useLogin();

const response = await login({ email, password });

if (response.session) {
  // Başarılı
} else if (response.error) {
  // Hata - yönet
  console.error(response.error);
} else {
  // Ağ veya bilinmeyen hata
  console.error('Giriş başarısız');
}
```

---

## Ayrıca Bak

- [Hızlı Başlangıç](./QUICKSTART.md) - Hook'ları öğren
- [CLI Kurulum](./CLI-SETUP.md) - Kurulum
- [Ara Yazılım Rehberi](./MIDDLEWARE.md) - Güvenlik ekle
- [Doğrulama Rehberi](./VALIDATION.md) - Oturumu kontrol et
