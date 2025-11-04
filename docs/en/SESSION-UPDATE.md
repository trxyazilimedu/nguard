# Session Update - Guide

Comprehensive guide for updating your session on both server and client sides.

## 🎯 Use Cases

- **Role Changes**: Upgrade/downgrade user roles
- **Permission Updates**: Dynamically update user permissions
- **Profile Updates**: Update user name, email, etc.
- **Preference Changes**: Update theme, language, notification settings
- **Premium Activation**: Upgrade user from free to premium

---

## 📍 Server-Side Session Update

### 1. Create API Route

`app/api/auth/update/route.ts`:

```typescript
import { nguard } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    // 1. Get current session from cookie
    const headers = Object.fromEntries(request.headers.entries());
    const currentSession = await nguard.validateSession(headers.cookie);

    if (!currentSession) {
      return Response.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // 2. Get update data from request body
    const { role, permissions, theme, language } = await request.json();

    // 3. Server-side validation - Protect sensitive operations!
    // Example: Only admins can change roles
    if (role && currentSession.data?.role !== 'admin') {
      return Response.json(
        { error: 'Unauthorized: Cannot change role' },
        { status: 403 }
      );
    }

    // 4. Update in database
    const updatedUser = await db.user.update({
      where: { id: currentSession.user.id },
      data: {
        role: role || currentSession.user.role,
        name: currentSession.user.name,
        email: currentSession.user.email,
      },
    });

    // 5. Create new session with updated data
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

    // 6. Return updated session
    return Response.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    console.error('Session update error:', error);
    return Response.json(
      { error: 'Failed to update session' },
      { status: 500 }
    );
  }
}
```

### 2. Validation with Callback

`lib/auth.ts`:

```typescript
import { initializeServer } from 'nguard/server';

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET!,
});

// Optional: Session update callback
nguard.onSession(async (session) => {
  // Add additional data
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

Simplest approach:

```typescript
'use client';

import { useSessionUpdate, useAuth } from 'nguard/client';

export function UpdateRoleButton() {
  const { user } = useAuth();
  const { updateSession, isLoading } = useSessionUpdate();

  const handleRoleChange = async () => {
    if (!user) return;

    try {
      // Send request to API
      const response = await fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      });

      if (!response.ok) {
        throw new Error('Failed to change role');
      }

      const data = await response.json();

      // Update session
      await updateSession(
        data.session.user,
        data.session.data
      );
    } catch (error) {
      alert(error instanceof Error ? error.message : 'An error occurred');
    }
  };

  return (
    <button onClick={handleRoleChange} disabled={isLoading}>
      {isLoading ? 'Updating...' : 'Make Admin'}
    </button>
  );
}
```

### 2. useSession Hook with More Control

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

      if (!response.ok) throw new Error('Failed to change theme');

      const data = await response.json();
      await updateSession(data.session.user, data.session.data);
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div>
      <button onClick={() => handleThemeChange('light')}>
        ☀️ Light Theme
      </button>
      <button onClick={() => handleThemeChange('dark')}>
        🌙 Dark Theme
      </button>
      <p>Current theme: {session?.data?.theme}</p>
    </div>
  );
}
```

---

## 🔄 Complete Example: Role Change Scenario

### Backend Code

`app/api/auth/update-role/route.ts`:

```typescript
import { nguard } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    // Get session
    const headers = Object.fromEntries(request.headers.entries());
    const session = await nguard.validateSession(headers.cookie);

    if (!session) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Only admins can change roles
    if (session.data?.role !== 'admin') {
      return Response.json(
        { error: 'Only admins can change roles' },
        { status: 403 }
      );
    }

    const { userId, newRole } = await request.json();

    // Valid roles
    const validRoles = ['user', 'moderator', 'admin'];
    if (!validRoles.includes(newRole)) {
      return Response.json(
        { error: 'Invalid role' },
        { status: 400 }
      );
    }

    // Find user
    const targetUser = await db.user.findUnique({
      where: { id: userId },
    });

    if (!targetUser) {
      return Response.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    // Update role
    const updatedUser = await db.user.update({
      where: { id: userId },
      data: { role: newRole },
    });

    // Create audit log
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
    console.error('Role update error:', error);
    return Response.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}
```

### Frontend Code

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

  // Load all users
  const loadUsers = async () => {
    try {
      const res = await fetch('/api/users');
      const data = await res.json();
      setUsers(data.users);
    } catch (error) {
      console.error('Failed to load users:', error);
    }
  };

  // Change user role
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

      // Update list
      setUsers(users.map(u =>
        u.id === userId ? { ...u, role: newRole } : u
      ));

      alert('Role changed successfully');

      // If changing own role, update session
      if (userId === currentUser?.id) {
        // Note: Only admins can change roles in this example
        // So this branch would only execute for admin-to-admin changes
      }
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Failed to change role');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>Admin Panel</h1>
      <button onClick={loadUsers}>Load Users</button>

      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>Actions</th>
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
// ✅ GOOD - Validate all operations on server
const handleRoleUpdate = async (userId: string, newRole: string) => {
  // 1. Check session
  if (!session) throw new Error('Unauthorized');

  // 2. Check permissions
  if (session.data?.role !== 'admin') {
    throw new Error('Unauthorized');
  }

  // 3. Validate role
  if (!['user', 'moderator', 'admin'].includes(newRole)) {
    throw new Error('Invalid role');
  }

  // 4. Check user exists
  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error('User not found');

  // 5. Save changes
  return db.user.update({ where: { id: userId }, data: { role: newRole } });
};

// ❌ BAD - Trust client data
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
      { error: 'Too many requests. Please try again later' },
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
// Log every session update
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

## 🔄 Flow Diagram

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

## 💡 Best Practices Summary

| ✅ DO | ❌ DON'T |
|------|---------|
| Server-side validation | Trust client data |
| Rate limiting | Unlimited requests |
| Audit logging | No logging |
| Permission checks | Skip authorization |
| HTTPS only | HTTP cookies |
| Secure secret | Weak secret |
| Generic error messages | Detailed error messages |
| Session expiry | Never expire |
| Validate role values | Accept any string |
| Atomic updates | Partial updates |

---

## 🔗 Related Pages

- [API-SERVER.md](./API-SERVER.md) - Server API details
- [API-CLIENT.md](./API-CLIENT.md) - Client hooks details
- [CALLBACKS.md](./CALLBACKS.md) - How callbacks work
- [BEST-PRACTICES.md](./BEST-PRACTICES.md) - Security and best practices
