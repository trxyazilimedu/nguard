# Client API Referansı

Nguard'da client-side hooks ve component'lerin kapsamlı dokümantasyonu.

## Genel Bakış

Nguard, authentication yönetimi için React hooks sağlar. Tüm authentication fonksiyonları artık hata fırlatmak yerine yapılandırılmış response objesi döndürür.

## Response Tipleri

### LoginResponse

`login()` fonksiyonu tarafından döndürülür.

```typescript
interface LoginResponse {
  success: boolean;           // Giriş başarılı mı
  message: string;            // "Login başarılı" veya hata açıklaması
  user?: SessionUser;         // Kullanıcı bilgileri (başarılıysa)
  data?: SessionData;         // Role gibi session verileri (başarılıysa)
  error?: string;             // Hata mesajı (başarısızsa)
}
```

**Örnek:**

```typescript
const response = await login({ email, password });

if (response.success) {
  console.log(response.user);   // { id, email, name }
  console.log(response.data);   // { role: 'admin' }
} else {
  console.log(response.error);  // "Geçersiz kimlik bilgileri"
}
```

### LogoutResponse

`logout()` fonksiyonu tarafından döndürülür.

```typescript
interface LogoutResponse {
  success: boolean;           // Çıkış başarılı mı
  message: string;            // "Çıkış başarılı" veya hata açıklaması
  error?: string;             // Hata mesajı (başarısızsa)
}
```

**Örnek:**

```typescript
const response = await logout();

if (response.success) {
  console.log('Başarıyla çıkış yapıldı');
} else {
  console.log('Çıkış hatası:', response.error);
}
```

### UpdateSessionResponse

`updateSession()` fonksiyonu tarafından döndürülür.

```typescript
interface UpdateSessionResponse {
  success: boolean;           // Güncelleme başarılı mı
  message: string;            // "Session güncellendi" veya hata açıklaması
  session?: Session;          // Güncellenen session (başarılıysa)
  error?: string;             // Hata mesajı (başarısızsa)
}
```

**Örnek:**

```typescript
const response = await updateSession(updatedUser, updatedData);

if (response.success) {
  console.log('Session güncellendi:', response.session);
} else {
  console.log('Güncelleme hatası:', response.error);
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
  login: (credentials: any) => Promise<LoginResponse>;
  logout: () => Promise<LogoutResponse>;
}
```

---

## Sonraki Adımlar

- [QUICKSTART.md](./QUICKSTART.md) - Kurulum rehberi
- [SESSION-UPDATE.md](./SESSION-UPDATE.md) - Session verisini güncelle
