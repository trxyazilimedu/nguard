# Session Güncelleme - Rehber

Mevcut session'ı serverda ve clientda güncellemek için kapsamlı rehber.

## 🎯 Kullanım Senaryoları

- **Rol Değişimi**: Kullanıcının rolünü upgrade/downgrade etme
- **İzin Değişimi**: Kullanıcının permission'larını dinamik olarak güncelleme
- **Profil Güncelleme**: Kullanıcı adı, email vb. güncellemeler
- **Preference Değişimi**: Tema, dil, bildirim ayarları
- **Premium Aktivasyon**: Kullanıcıyı free'den premium'a yükseltme

---

## 📍 Server-Side Session Update

### 1. API Route Oluştur

`app/api/auth/update/route.ts`:

```typescript
import { nguard } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    // 1. Cookie'den mevcut session'ı al
    const headers = Object.fromEntries(request.headers.entries());
    const currentSession = await nguard.validateSession(headers.cookie);

    if (!currentSession) {
      return Response.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // 2. Request body'den güncelleme verilerini al
    const { role, permissions, theme, language } = await request.json();

    // 3. Server-side validation - Riskli işlemler koru!
    // Örnek: Sadece admin'ler başka kullanıcıları güncelleyebilir
    if (role && currentSession.data?.role !== 'admin') {
      return Response.json(
        { error: 'Yetkisiz: Rol değiştiremezsiniz' },
        { status: 403 }
      );
    }

    // 4. Veritabanında güncelle
    const updatedUser = await db.user.update({
      where: { id: currentSession.user.id },
      data: {
        role: role || currentSession.user.role,
        name: currentSession.user.name,
        email: currentSession.user.email,
      },
    });

    // 5. Yeni session oluştur (güncellenmiş verilerle)
    const { session, setCookieHeader } = await nguard.createSession(
      {
        id: updatedUser.id,
        email: updatedUser.email,
        name: updatedUser.name,
      },
      {
        role: role || currentSession.data?.role,
        permissions: permissions || currentSession.data?.permissions,
        theme: theme || currentSession.data?.theme,
        language: language || currentSession.data?.language,
      }
    );

    // 6. Güncellenmiş session döndür
    return Response.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    console.error('Session update error:', error);
    return Response.json(
      { error: 'Session güncelleme başarısız' },
      { status: 500 }
    );
  }
}
```

### 2. Callback ile Validasyon

`lib/auth.ts`:

```typescript
import { initializeServer } from 'nguard/server';

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET!,
});

// Session güncellemesi için callback (opsiyonel)
nguard.onSession(async (session) => {
  // Diğer veriler ekle
  const user = await db.user.findUnique({
    where: { id: session.user.id },
    include: { permissions: true }
  });

  return {
    ...session,
    data: {
      ...session.data,
      permissions: user?.permissions.map(p => p.name) || [],
      lastUpdated: new Date().toISOString(),
    }
  };
});
```

---

## 📍 Client-Side Session Update

### 1. useSessionUpdate Hook

En basit yöntem:

```typescript
'use client';

import { useSessionUpdate, useAuth } from 'nguard/client';

export function UpdateRoleButton() {
  const { user } = useAuth();
  const { updateSession, isLoading } = useSessionUpdate();

  const handleRoleChange = async () => {
    if (!user) return;

    try {
      // API'ye istek gönder
      const response = await fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      });

      if (!response.ok) {
        throw new Error('Rol değişimi başarısız');
      }

      const data = await response.json();

      // Session'ı güncelle
      await updateSession(
        data.session.user,
        data.session.data
      );
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Hata oluştu');
    }
  };

  return (
    <button onClick={handleRoleChange} disabled={isLoading}>
      {isLoading ? 'Güncelleniyor...' : 'Rolu Admin Yap'}
    </button>
  );
}
```

### 2. useSession Hook ile Detaylı Kontrol

```typescript
'use client';

import { useSession } from 'nguard/client';

export function SettingsPanel() {
  const { session, updateSession, isLoading } = useSession();

  const handleThemeChange = async (theme: 'light' | 'dark') => {
    if (!session) return;

    try {
      const response = await fetch('/api/auth/update', {
        method: 'POST',
        body: JSON.stringify({ theme }),
      });

      if (!response.ok) throw new Error('Tema değişimi başarısız');

      const data = await response.json();
      await updateSession(data.session.user, data.session.data);
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div>
      <button onClick={() => handleThemeChange('light')}>
        ☀️ Açık Tema
      </button>
      <button onClick={() => handleThemeChange('dark')}>
        🌙 Koyu Tema
      </button>
      <p>Mevcut tema: {session?.data?.theme}</p>
    </div>
  );
}
```

---

## 🔄 Tam Örnek: Rol Değişimi Senaryosu

### Backend Kodu

`app/api/auth/update-role/route.ts`:

```typescript
import { nguard } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    // Session'ı al
    const headers = Object.fromEntries(request.headers.entries());
    const session = await nguard.validateSession(headers.cookie);

    if (!session) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Sadece admin'ler rol değiştirebilir
    if (session.data?.role !== 'admin') {
      return Response.json(
        { error: 'Sadece admin rol değiştirebilir' },
        { status: 403 }
      );
    }

    const { userId, newRole } = await request.json();

    // Geçerli roller
    const validRoles = ['user', 'moderator', 'admin'];
    if (!validRoles.includes(newRole)) {
      return Response.json(
        { error: 'Geçersiz rol' },
        { status: 400 }
      );
    }

    // Kullanıcıyı bul
    const targetUser = await db.user.findUnique({
      where: { id: userId },
    });

    if (!targetUser) {
      return Response.json(
        { error: 'Kullanıcı bulunamadı' },
        { status: 404 }
      );
    }

    // Rol'ü güncelle
    const updatedUser = await db.user.update({
      where: { id: userId },
      data: { role: newRole },
    });

    // Audit log tutuş
    await db.auditLog.create({
      userId: session.user.id,
      action: 'UPDATE_USER_ROLE',
      targetUserId: userId,
      changes: { role: { from: targetUser.role, to: newRole } },
      timestamp: new Date(),
    });

    return Response.json({
      ok: true,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
      }
    });
  } catch (error) {
    console.error('Rol güncelleme hatası:', error);
    return Response.json(
      { error: 'Sunucu hatası' },
      { status: 500 }
    );
  }
}
```

### Frontend Kodu

`components/AdminPanel.tsx`:

```typescript
'use client';

import { useState } from 'react';
import { useAuth, useSession } from 'nguard/client';

interface User {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'moderator' | 'admin';
}

export function AdminPanel() {
  const { user: currentUser } = useAuth();
  const { updateSession } = useSession();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);

  // Tüm kullanıcıları yükle
  const loadUsers = async () => {
    try {
      const res = await fetch('/api/users');
      const data = await res.json();
      setUsers(data.users);
    } catch (error) {
      console.error('Kullanıcı yükleme hatası:', error);
    }
  };

  // Kullanıcı rolünü değiştir
  const changeUserRole = async (userId: string, newRole: string) => {
    setLoading(true);
    try {
      const response = await fetch('/api/auth/update-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newRole }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error);
      }

      const data = await response.json();

      // Listeyi güncelle
      setUsers(users.map(u =>
        u.id === userId ? { ...u, role: newRole } : u
      ));

      alert('Rol başarıyla değiştirildi');

      // Eğer kendi rolünü değiştirdiyse, session'ı güncelle
      if (userId === currentUser?.id) {
        // Not: Bu örneğe göre sadece admin'ler rol değiştirebilir
        // So this branch would only execute for admin-to-admin changes
      }
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Rol değişimi başarısız');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>Admin Paneli</h1>
      <button onClick={loadUsers}>Kullanıcıları Yükle</button>

      <table>
        <thead>
          <tr>
            <th>Ad</th>
            <th>Email</th>
            <th>Rol</th>
            <th>İşlemler</th>
          </tr>
        </thead>
        <tbody>
          {users.map(user => (
            <tr key={user.id}>
              <td>{user.name}</td>
              <td>{user.email}</td>
              <td>{user.role}</td>
              <td>
                <select
                  value={user.role}
                  onChange={(e) => changeUserRole(user.id, e.target.value)}
                  disabled={loading}
                >
                  <option value="user">User</option>
                  <option value="moderator">Moderator</option>
                  <option value="admin">Admin</option>
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

---

## 🔒 Security Best Practices

### 1. Server-Side Validation

```typescript
// ✅ GOOD - Tüm işlemleri server'da doğrula
const handleRoleUpdate = async (userId: string, newRole: string) => {
  // 1. Session'ı kontrol et
  if (!session) throw new Error('Unauthorized');

  // 2. Permission'ı kontrol et
  if (session.data?.role !== 'admin') {
    throw new Error('Yetkisiz');
  }

  // 3. Geçerli rol olup olmadığını kontrol et
  if (!['user', 'moderator', 'admin'].includes(newRole)) {
    throw new Error('Geçersiz rol');
  }

  // 4. Kullanıcıyı kontrol et
  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error('Kullanıcı bulunamadı');

  // 5. Güncellemeleri kaydet
  return db.user.update({ where: { id: userId }, data: { role: newRole } });
};

// ❌ BAD - Client'ten gelen verilere güven
const handleRoleUpdate = async (userId: string, newRole: string) => {
  // No validation! Direct update
  await db.user.update({ where: { id: userId }, data: { role: newRole } });
};
```

### 2. Rate Limiting

```typescript
const updateAttempts = new Map<string, number>();

export async function POST(request: Request) {
  const session = await nguard.validateSession(headers.cookie);
  const key = `${session.user.id}:update`;

  const attempts = updateAttempts.get(key) || 0;
  if (attempts > 10) {
    return Response.json(
      { error: 'Çok fazla istek. Lütfen bir süre sonra tekrar deneyin' },
      { status: 429 }
    );
  }

  updateAttempts.set(key, attempts + 1);
  setTimeout(() => updateAttempts.delete(key), 60000); // 1 minute

  // ... rest of logic
}
```

### 3. Audit Logging

```typescript
// Her session günclemesini kaydet
const { session, setCookieHeader } = await nguard.createSession(user, data);

await db.auditLog.create({
  userId: user.id,
  action: 'SESSION_UPDATE',
  changes: {
    role: oldSession.data?.role,
    theme: oldSession.data?.theme,
  },
  newValues: data,
  ipAddress: request.ip,
  userAgent: request.headers.get('user-agent'),
  timestamp: new Date(),
});
```

---

## 🔗 Flow Diagramı

```
┌─────────────────────────────────────────────────────────────┐
│                    User Action                               │
│              (e.g., Change Theme Button)                    │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│            Client Component (updateSession)                  │
│              const { updateSession } = useSession()         │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│          Fetch POST /api/auth/update                        │
│          { theme: 'dark' }                                  │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│         Server: Validate Session                             │
│         Check: isAuthenticated? Permission? Role?           │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│         Server: Update Database                              │
│         UPDATE user SET theme = 'dark'                      │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│      Server: Create New Session (with new data)            │
│      nguard.createSession(user, { theme: 'dark' })        │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│     Server: Return New Token + Set-Cookie                   │
│     Response: { session: {...}, setCookieHeader }          │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│   Client: updateSession(user, data)                         │
│   Updates SessionProvider state                             │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│    Components Re-render with New Session Data               │
│    useAuth() returns updated { user, data }                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 💡 Best Practices Özeti

| ✅ DO | ❌ DON'T |
|------|---------|
| Server-side validation | Trust client data |
| Rate limiting | Unlimited requests |
| Audit logging | No logging |
| Permission checks | Skip authorization |
| HTTPS only | HTTP cookies |
| Secure secret | Weak secret |
| Error messages (generic) | Detailed error messages |
| Session expiry | Never expire |
| Validate role values | Accept any string |
| Atomic updates | Partial updates |

---

## 🔗 İlgili Sayfalar

- [API-SERVER.md](./API-SERVER.md) - Server API detayları
- [API-CLIENT.md](./API-CLIENT.md) - Client hooks detayları
- [CALLBACKS.md](./CALLBACKS.md) - Callback'ler nasıl çalışır
- [BEST-PRACTICES.md](./BEST-PRACTICES.md) - Güvenlik ve best practices
