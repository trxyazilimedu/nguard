# Nguard - English Documentation

Welcome! Here you'll find comprehensive English documentation for Nguard.

## 📚 Guides

### Getting Started
1. **[Quick Start](./QUICKSTART.md)** - 5-minute setup
2. **[Getting Started](./GETTING-STARTED.md)** - Detailed first project

### API Reference
3. **[Server API](./API-SERVER.md)** - Server-side functions
4. **[Client API](./API-CLIENT.md)** - Client hooks and components
5. **[Callbacks](./CALLBACKS.md)** - Callbacks and how to use them

### Advanced Topics
6. **[Session Update](./SESSION-UPDATE.md)** - Updating existing sessions
7. **[Examples](./EXAMPLES.md)** - Real-world examples
8. **[Best Practices](./BEST-PRACTICES.md)** - Best practices
9. **[Middleware](./MIDDLEWARE.md)** - Route protection

## 🚀 Quick Start

```bash
# 1. Install
npm install nguard

# 2. Read QUICKSTART.md
# 3. Implement callbacks
# 4. Create API routes
# 5. Setup SessionProvider
# 6. Use useAuth()
```

## 📚 Documentation Map

| Page | Description |
|------|-------------|
| [QUICKSTART.md](./QUICKSTART.md) | 5-minute setup |
| [GETTING-STARTED.md](./GETTING-STARTED.md) | Detailed first setup |
| [API-SERVER.md](./API-SERVER.md) | Server functions and callbacks |
| [API-CLIENT.md](./API-CLIENT.md) | Client hooks and SessionProvider |
| [CALLBACKS.md](./CALLBACKS.md) | How callbacks work |
| [SESSION-UPDATE.md](./SESSION-UPDATE.md) | Session update guide and examples |
| [EXAMPLES.md](./EXAMPLES.md) | Real-world examples |
| [BEST-PRACTICES.md](./BEST-PRACTICES.md) | Security and best practices |
| [MIDDLEWARE.md](./MIDDLEWARE.md) | Next.js middleware setup |

## 🤔 What Are You Looking For?

**I want to get started quickly**
→ [QUICKSTART.md](./QUICKSTART.md)

**I want to understand server callbacks**
→ [CALLBACKS.md](./CALLBACKS.md) → [API-SERVER.md](./API-SERVER.md)

**I want to setup the client side**
→ [API-CLIENT.md](./API-CLIENT.md) → [EXAMPLES.md](./EXAMPLES.md)

**I'm integrating with Spring backend**
→ [EXAMPLES.md](./EXAMPLES.md) → [CALLBACKS.md](./CALLBACKS.md)

**I have security questions**
→ [BEST-PRACTICES.md](./BEST-PRACTICES.md)

**I want to protect routes**
→ [MIDDLEWARE.md](./MIDDLEWARE.md)

**I want to update my session (role, theme, etc.)**
→ [SESSION-UPDATE.md](./SESSION-UPDATE.md)

## 💡 Core Concepts

### Callback System
Nguard's heart is callbacks. You:
- **Server-side**: User auth, token validation, cleanup
- **Client-side**: Frontend login, logout, init

### Flow
```
User Login Form
    ↓
useAuth().login(credentials)
    ↓
Client onLogin callback
    ↓
POST /api/auth/login
    ↓
Server onServerLogin callback
    ↓
JWT + Cookie
    ↓
useAuth() state update
    ↓
Component re-render ✅
```

## 🚀 First Steps

1. Read this README (5 min)
2. Follow [QUICKSTART.md](./QUICKSTART.md) (5 min)
3. Read [CALLBACKS.md](./CALLBACKS.md) (10 min)
4. Check [EXAMPLES.md](./EXAMPLES.md) (10 min)
5. Start coding!

---

**Türkçe mi?** → Bkz. [../../docs/tr/](../../docs/tr/README.md)
