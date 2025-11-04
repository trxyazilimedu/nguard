# Nguard - Next.js 16+ Session Management Library

## 🚀 Just Shipped: Nguard v0.3.4

I'm excited to announce the latest release of **Nguard**, a powerful yet simple session management library for Next.js 16+.

### What is Nguard?

Nguard is a **zero-config authentication solution** that makes session management effortless. It provides:

✅ **JWT-based Sessions** - Secure, stateless authentication
✅ **Zero Configuration** - Works out of the box with `npx nguard-setup`
✅ **TypeScript First** - 100% type-safe
✅ **Works with Any Backend** - Spring, Express, Django, Python, or any REST API
✅ **Server & Client Hooks** - Both server components and client-side hooks
✅ **Built-in Middleware** - Role-based access control, rate limiting, CORS
✅ **Session Validation** - Validate and refresh sessions anytime

### Key Features in v0.3.4

**Server-Side Session Management:**
```typescript
import { nguard } from '@/lib/auth';

// Create session
const { session, setCookieHeader } = await nguard.createSession({
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  expires: Date.now() + 24 * 60 * 60 * 1000,
});

// Logout with cleanup
const cookieHeader = await nguard.logout(session);
```

**Client-Side Hooks:**
```typescript
const { session, loading } = useSession();
const { login, isLoading } = useLogin();
const { logout, isLoading } = useLogout();
const { validate, isValid } = useValidateSession();
```

**Server Components:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();
  return <div>Welcome, {session?.email}</div>;
}
```

### How It Works

1. **Install**: `npm install nguard`
2. **Setup**: `npx nguard-setup` - Interactive wizard
3. **Use**: Start building with hooks and server functions

The wizard automatically creates:
- `lib/auth.ts` - Server utilities
- API routes for login, logout, validate, refresh
- `proxy.ts` - Next.js 16 middleware configuration
- Environment template

### Why Nguard?

- **No vendor lock-in** - Works with your existing backend
- **Flexible session structure** - Store any data you need
- **Production-ready** - HTTP-only cookies, CSRF protection, JWT validation
- **Developer-friendly** - Great DX with TypeScript and hooks
- **Composable middleware** - Build complex auth flows easily

### Documentation

Complete documentation available in English and Turkish:
- 📖 CLI Setup Guide
- 🚀 Quick Start
- 📚 API Reference
- ⚙️ Middleware Guide
- ✔️ Session Validation Guide

### Getting Started

```bash
npm install nguard
npx nguard-setup
```

Then wrap your app:
```typescript
import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }) {
  return (
    <SessionProvider>
      {children}
    </SessionProvider>
  );
}
```

### GitHub

Open source and free to use. Check it out:
https://github.com/trxyazilimedu/nguard

### npm

Available on npm registry:
https://www.npmjs.com/package/nguard

---

**Have feedback or suggestions?** Open an issue on GitHub or reach out!

Looking forward to building amazing authentication solutions together! 🔐

#NextJS #Authentication #JWT #TypeScript #OpenSource #WebDevelopment #React
