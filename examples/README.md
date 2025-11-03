# Session Update Examples

Bu klasörde, Nguard ile session güncelleme işlemlerinin tam örnekleri bulunmaktadır.

## 📁 Dosyalar

### Frontend (Next.js)

#### 1. **api-update-role.ts**
- **Amaç**: Kullanıcı rolü güncellemek için API route
- **Endpoint**: `POST /api/auth/update-role`
- **Kullanım**:
  ```typescript
  fetch('/api/auth/update-role', {
    method: 'POST',
    body: JSON.stringify({ userId: 'user-123', newRole: 'admin' })
  })
  ```
- **Özellikler**:
  - Session validasyonu
  - Permission kontrolü (sadece admin'ler)
  - Backend API çağrısı
  - Yeni session oluşturma
  - Error handling

#### 2. **api-update-session.ts**
- **Amaç**: Kullanıcı tercihlerini güncellemek (tema, dil, bildirimler)
- **Endpoint**: `POST /api/auth/update`
- **Kullanım**:
  ```typescript
  fetch('/api/auth/update', {
    method: 'POST',
    body: JSON.stringify({ theme: 'dark', language: 'tr' })
  })
  ```
- **Güncellenebilen Alanlar**:
  - `theme`: 'light' | 'dark'
  - `language`: 'en' | 'tr'
  - `notifications`: boolean
  - `twoFactorEnabled`: boolean

#### 3. **components-update-session.tsx**
- **Amaç**: Session güncellemelerinin tamamen çalışan React componentleri
- **İçeriği**:
  1. **ThemeSwitcher** - Tema değiştirme
  2. **LanguageSelector** - Dil seçimi
  3. **SettingsPanel** - Çok seçenekli ayarlar
  4. **AdminPanel** - Admin tarafından kullanıcı rol değişimi
  5. **ProfileUpdate** - Profil bilgilerini güncelleme

- **Kullanım**:
  ```typescript
  import { ThemeSwitcher } from '@/examples/components-update-session';

  export default function MyPage() {
    return <ThemeSwitcher />;
  }
  ```

### Backend (Spring Boot)

#### 4. **backend-update-role-spring.java**
- **Amaç**: Rolü güncellemek için Spring controller
- **Endpoint**: `PATCH /api/users/{userId}/role`
- **Request Body**:
  ```json
  {
    "role": "admin",
    "updatedBy": "admin-user-id"
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "message": "User role updated successfully",
    "user": {
      "id": "user-123",
      "email": "user@example.com",
      "role": "admin"
    }
  }
  ```

#### 5. **backend-update-preferences-spring.java**
- **Amaç**: Kullanıcı tercihlerini güncellemek
- **Endpoint**: `PATCH /api/users/{userId}/preferences`
- **Request Body**:
  ```json
  {
    "theme": "dark",
    "language": "tr",
    "notifications": true,
    "twoFactorEnabled": false
  }
  ```
- **Özellikler**:
  - Tercih validasyonu
  - Kullanıcılar sadece kendi tercihlerini güncelleyebilir
  - Audit log oluşturma

#### 6. **backend-dtos-spring.java**
- **Amaç**: Backend DTO sınıfları
- **İçeriği**:
  - `UpdateRoleRequest` - Rol güncelleme isteği
  - `UpdatePreferencesRequest` - Tercih güncelleme isteği
  - `UserResponse` - Kullanıcı yanıt DTO
  - `AuditLogRequest` - Audit log isteği
  - `ErrorResponse` - Standart hata yanıtı

### Konfigürasyon

#### 7. **.env.example**
- **Amaç**: Ortam değişkenleri template
- **Temel Değişkenler**:
  ```
  BACKEND_API_URL=http://localhost:8080/api
  NGUARD_SECRET=your-secure-key
  NODE_ENV=development
  ```

## 🚀 Kurulum ve Kullanım

### 1. Frontend Kurulumu

```bash
# Next.js projesine examples dosyalarını kopyala
cp examples/api-*.ts app/api/auth/
cp examples/components-*.tsx components/
```

### 2. Backend Kurulumu

```bash
# Spring projesine örnek dosyalarını kopyala
cp examples/backend-*.java src/main/java/com/example/auth/

# DTOları uygun klasörlere yerleştir
cp examples/backend-dtos-spring.java src/main/java/com/example/auth/dto/
```

### 3. Ortam Ayarları

```bash
# .env.example'i .env olarak kopyala
cp examples/.env.example .env

# Değişkenleri düzenle
BACKEND_API_URL=http://localhost:8080/api
NGUARD_SECRET=$(openssl rand -base64 32)
```

## 🔄 Flow Açıklaması

### Role Update Flow

```
1. Frontend (User Role Change)
   ↓
2. Component: changeUserRole(userId, newRole)
   ↓
3. POST /api/auth/update-role
   ↓
4. Next.js API Route (api-update-role.ts)
   - Session validasyonu
   - Permission kontrolü
   ↓
5. Backend API Call
   PATCH /api/users/{userId}/role
   ↓
6. Spring Controller (UserController.updateUserRole)
   - Rol validasyonu
   - Database güncelleme
   - Audit log
   ↓
7. Return Updated User
   ↓
8. Next.js Route: New Session Oluştur
   ↓
9. Return Response + Set-Cookie
   ↓
10. Frontend: updateSession() çalışır
    ↓
11. UI güncellemeleri
```

### Preferences Update Flow

```
1. Frontend (Theme/Language Change)
   ↓
2. Component: handleThemeChange('dark')
   ↓
3. POST /api/auth/update
   ↓
4. Next.js API Route (api-update-session.ts)
   - Session validasyonu
   - Tercih validasyonu
   ↓
5. Backend API Call
   PATCH /api/users/{userId}/preferences
   ↓
6. Spring Controller (PreferencesController.updatePreferences)
   - Güvenlik kontrolü
   - Database güncelleme
   - Audit log
   ↓
7. Return Updated User
   ↓
8. Next.js Route: New Session Oluştur
   ↓
9. Return Response + Set-Cookie
   ↓
10. Frontend: updateSession() çalışır
    ↓
11. UI güncellemeleri
```

## 🔒 Güvenlik Önerileri

### Frontend

- ✅ Server-side validation'a güven
- ✅ Sensitive data'ları validate et
- ✅ Error messages'ı logla
- ❌ Client'den gelen verilere güvenme

### Backend

- ✅ Her isteği authenticate et
- ✅ Permission kontrolü yap
- ✅ Input validation yap
- ✅ Audit log tutuş
- ✅ Rate limiting uygula
- ❌ Client-side validation'a güven

## 📝 Örnek Kullanımlar

### Tema Değiştirme

```typescript
// Frontend
const { updateSession } = useSessionUpdate();

await fetch('/api/auth/update', {
  method: 'POST',
  body: JSON.stringify({ theme: 'dark' })
});

// Backend
@PatchMapping("/{userId}/preferences")
public ResponseEntity<?> updatePreferences(...) {
  user.setTheme(request.getTheme());
  userService.save(user);
  // ...
}
```

### Rol Değişimi

```typescript
// Frontend
await fetch('/api/auth/update-role', {
  method: 'POST',
  body: JSON.stringify({ userId: '123', newRole: 'admin' })
});

// Backend
@PatchMapping("/{userId}/role")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> updateUserRole(...) {
  targetUser.setRole(request.getRole());
  userService.save(targetUser);
  // ...
}
```

## 🐛 Hata Giderme

### Backend'e ulaşamıyorum

```
❌ Error: Failed to fetch from backend API
✅ Çözüm:
  1. BACKEND_API_URL'i kontrol et
  2. Backend sunucusunun çalıştığını doğrula
  3. Network bağlantısını kontrol et
```

### Permission hatası alıyorum

```
❌ Error: Forbidden - Only admins can change user roles
✅ Çözüm:
  1. Kullanıcının admin olup olmadığını kontrol et
  2. Session data'sını kontrol et
  3. Backend validation'ını kontrol et
```

### Session güncellenmiyor

```
❌ Session değişmiyor
✅ Çözüm:
  1. Set-Cookie header'ını kontrol et
  2. updateSession() çalışıp çalışmadığını kontrol et
  3. SessionProvider çalışıp çalışmadığını doğrula
```

## 📚 İlgili Dokumentasyon

- [SESSION-UPDATE.md](../docs/tr/SESSION-UPDATE.md) - Detaylı rehber
- [API-SERVER.md](../docs/tr/API-SERVER.md) - Server API detayları
- [API-CLIENT.md](../docs/tr/API-CLIENT.md) - Client hooks detayları
- [CALLBACKS.md](../docs/tr/CALLBACKS.md) - Callback'ler

## 💡 Tips & Tricks

### Fetch isteğinde error handling

```typescript
try {
  const response = await fetch('/api/auth/update', {
    method: 'POST',
    body: JSON.stringify(data)
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error);
  }

  const result = await response.json();
  // ...
} catch (error) {
  console.error('Error:', error);
  // Show error to user
}
```

### Backend'te logging

```java
log.info("User {} updated preferences", currentUser.getId());
log.warn("Unauthorized attempt: {}", userId);
log.error("Failed to update preferences", exception);
```

### Type safety

```typescript
// DTOları TypeScript'e ekle
interface UpdatePreferencesRequest {
  theme?: 'light' | 'dark';
  language?: 'en' | 'tr';
  notifications?: boolean;
  twoFactorEnabled?: boolean;
}

// Tipi kullan
const request: UpdatePreferencesRequest = {
  theme: 'dark',
  language: 'tr'
};
```

---

**Not**: Bu örnekler production'a hazırdır, fakat kendi ihtiyaçlarınıza göre özelleştirmeniz gerekebilir.
