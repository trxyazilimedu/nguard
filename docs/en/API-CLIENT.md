# API Reference

Complete reference for all Nguard hooks and server functions.

## Client Hooks

### useSession()

Get the current session.

**Returns:**
```typescript
{
  session: Session | null;
  loading: boolean;
}
```

**Example:**
```typescript
const { session, loading } = useSession();

if (loading) return <div>Loading...</div>;
return <div>{session?.email}</div>;
```

---

### useLogin()

Login with email and password.

**Returns:**
```typescript
{
  login: (credentials: { email: string; password: string }) => Promise<any>;
  isLoading: boolean;
}
```

**Example:**
```typescript
const { login, isLoading } = useLogin();

const response = await login({ email, password });
if (response.session) {
  // Success
} else if (response.error) {
  // Error
}
```

---

### useLogout()

Logout the current user.

**Returns:**
```typescript
{
  logout: () => Promise<void>;
  isLoading: boolean;
}
```

**Example:**
```typescript
const { logout, isLoading } = useLogout();

await logout();
// User is logged out
```

---

### useSessionUpdate()

Update session data without re-login.

**Returns:**
```typescript
{
  updateSession: (sessionData: any) => Promise<void>;
  isLoading: boolean;
}
```

**Example:**
```typescript
const { updateSession, isLoading } = useSessionUpdate();

const newSession = { ...session, role: 'admin' };
await updateSession(newSession);
```

---

### useValidateSession()

Check if the current session is valid.

**Returns:**
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

**Example:**
```typescript
const { validate, isValid, validationResult } = useValidateSession();

await validate();

if (isValid) {
  console.log('Session is valid');
  console.log('Expires in:', validationResult?.expiresIn);
} else {
  console.log('Error:', validationResult?.error);
}
```

---

### useAuth()

Alternative hook that returns more properties.

**Returns:**
```typescript
{
  session: Session | null;
  isAuthenticated: boolean;
  login: (credentials: any) => Promise<any>;
  logout: () => Promise<void>;
  isLoading: boolean;
}
```

**Example:**
```typescript
const { session, isAuthenticated, login, logout, isLoading } = useAuth();

if (!isAuthenticated) {
  return <LoginForm onLogin={login} />;
}

return (
  <div>
    <p>{session?.email}</p>
    <button onClick={logout}>Logout</button>
  </div>
);
```

---

## Components

### SessionProvider

Provides session state to all child components.

**Props:**
```typescript
{
  children?: ReactNode;
  onLogin?: LoginCallback; // Optional
  onLogout?: LogoutCallback; // Optional
}
```

**Example:**
```typescript
<SessionProvider>
  <App />
</SessionProvider>
```

**With custom callbacks:**
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

## Server Functions

### auth()

Get the current session in Server Components.

**Returns:**
```typescript
Promise<Session | null>
```

**Example:**
```typescript
import { auth } from '@/lib/auth';

export default async function Page() {
  const session = await auth();

  if (!session) {
    return <div>Not authenticated</div>;
  }

  return <div>Hello {session.email}</div>;
}
```

---

### nguard.createSession()

Create a new session with flexible session data.

**Parameters:**
```typescript
createSession(sessionData: {
  [key: string]: any;
  expires: number;
}): Promise<{
  session: Session;
  setCookieHeader: string;
}>
```

**Example:**
```typescript
import { nguard } from '@/lib/auth';

const { session, setCookieHeader } = await nguard.createSession({
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  permissions: ['read', 'write'],
  expires: Date.now() + 24 * 60 * 60 * 1000,
});

// Return to client with Set-Cookie header
return NextResponse.json({ session }, {
  headers: { 'Set-Cookie': setCookieHeader }
});
```

---

### nguard.clearSession()

Clear the session cookie.

**Returns:**
```typescript
string // Cookie header to clear session
```

**Example:**
```typescript
import { nguard } from '@/lib/auth';

const cookieHeader = nguard.clearSession();

return NextResponse.json({ ok: true }, {
  headers: { 'Set-Cookie': cookieHeader }
});
```

---

### nguard.validateSession()

Validate a session token from a cookie string.

**Parameters:**
```typescript
validateSession(cookieString: string): Promise<Session | null>
```

**Example:**
```typescript
import { nguard } from '@/lib/auth';

const session = await nguard.validateSession(cookieString);

if (!session) {
  return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
}

// Session is valid
return NextResponse.json({ session });
```

---

## Types

### Session

```typescript
interface Session {
  [key: string]: any;  // Any properties your backend provides
  expires: number;      // Expiration timestamp in milliseconds
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

## Response Patterns

Your API responses can have any structure. Nguard returns them as-is:

### Login Success
```typescript
{
  session: {
    id: 'user-123',
    email: 'user@example.com',
    role: 'admin'
  }
}
```

### Login With Message
```typescript
{
  success: true,
  message: 'Logged in successfully',
  session: { /* ... */ }
}
```

### Login Error
```typescript
{
  success: false,
  error: 'Invalid credentials'
}
```

---

## Error Handling

All hooks return responses with error information:

```typescript
const { login } = useLogin();

const response = await login({ email, password });

if (response.session) {
  // Success
} else if (response.error) {
  // Error - handle it
  console.error(response.error);
} else {
  // Network or unknown error
  console.error('Login failed');
}
```

---

## See Also

- [Quick Start](./QUICKSTART.md) - Learn hooks
- [CLI Setup](./CLI-SETUP.md) - Installation
- [Middleware Guide](./MIDDLEWARE.md) - Add security
- [Validation Guide](./VALIDATION.md) - Check session
