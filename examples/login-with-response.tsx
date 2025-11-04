/**
 * Login Component with Response Handling
 *
 * Shows how to use the new login/logout response messages
 */

'use client';

import { useAuth } from 'nguard/client';
import { FormEvent, useState } from 'react';

export function LoginFormWithResponse() {
  const { login, isLoading } = useAuth();
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function handleLogin(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSuccessMessage(null);
    setErrorMessage(null);

    const formData = new FormData(e.currentTarget);
    const email = formData.get('email') as string;
    const password = formData.get('password') as string;

    // login() now returns LoginResponse with success, message, user, data
    const response = await login({ email, password });

    if (response.success) {
      // ✅ Login başarılı
      setSuccessMessage(response.message); // "Login successful"
      console.log('User:', response.user);
      console.log('Data:', response.data);

      // Redirect or update UI
      // router.push('/dashboard');
    } else {
      // ❌ Login başarısız
      setErrorMessage(response.error || response.message); // "Invalid credentials"
    }
  }

  return (
    <div style={{ maxWidth: '400px', margin: '2rem auto' }}>
      <h1>Login</h1>

      {successMessage && (
        <div style={{
          backgroundColor: '#d4edda',
          color: '#155724',
          padding: '1rem',
          borderRadius: '4px',
          marginBottom: '1rem'
        }}>
          ✅ {successMessage}
        </div>
      )}

      {errorMessage && (
        <div style={{
          backgroundColor: '#f8d7da',
          color: '#721c24',
          padding: '1rem',
          borderRadius: '4px',
          marginBottom: '1rem'
        }}>
          ❌ {errorMessage}
        </div>
      )}

      <form onSubmit={handleLogin}>
        <div style={{ marginBottom: '1rem' }}>
          <label>
            Email:
            <input
              type="email"
              name="email"
              required
              disabled={isLoading}
              style={{ display: 'block', width: '100%', marginTop: '0.5rem' }}
            />
          </label>
        </div>

        <div style={{ marginBottom: '1rem' }}>
          <label>
            Password:
            <input
              type="password"
              name="password"
              required
              disabled={isLoading}
              style={{ display: 'block', width: '100%', marginTop: '0.5rem' }}
            />
          </label>
        </div>

        <button
          type="submit"
          disabled={isLoading}
          style={{ width: '100%', padding: '0.5rem' }}
        >
          {isLoading ? '⏳ Logging in...' : '🔓 Login'}
        </button>
      </form>
    </div>
  );
}

// ============================================================================
// Logout Component with Response
// ============================================================================

export function LogoutButtonWithResponse() {
  const { logout, isLoading } = useAuth();
  const [message, setMessage] = useState<string | null>(null);

  async function handleLogout() {
    // logout() now returns LogoutResponse with success and message
    const response = await logout();

    if (response.success) {
      setMessage(response.message); // "Logout successful"
      console.log('Logged out successfully');
    } else {
      setMessage(response.error || response.message); // Error message
      console.error('Logout error:', response.error);
    }
  }

  return (
    <div>
      {message && (
        <p style={{ fontSize: '0.9rem', margin: '0.5rem 0' }}>
          {message}
        </p>
      )}
      <button
        onClick={handleLogout}
        disabled={isLoading}
        style={{
          padding: '0.5rem 1rem',
          backgroundColor: '#dc3545',
          color: 'white',
          border: 'none',
          borderRadius: '4px',
          cursor: 'pointer'
        }}
      >
        {isLoading ? '⏳ Logging out...' : '🚪 Logout'}
      </button>
    </div>
  );
}

// ============================================================================
// Update Session Component with Response
// ============================================================================

import { useSessionUpdate } from 'nguard/client';

export function UpdatePreferencesWithResponse() {
  const { updateSession, isLoading } = useSessionUpdate();
  const [message, setMessage] = useState<string | null>(null);
  const [messageType, setMessageType] = useState<'success' | 'error' | null>(null);

  async function handleThemeChange(theme: 'light' | 'dark') {
    setMessage(null);

    // Call API to update theme
    const response = await fetch('/api/auth/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme })
    });

    const data = await response.json();

    // updateSession() now returns UpdateSessionResponse
    const updateResponse = await updateSession(
      data.session.user,
      data.session.data
    );

    if (updateResponse.success) {
      setMessageType('success');
      setMessage(updateResponse.message); // "Session updated successfully"
      console.log('Updated session:', updateResponse.session);
    } else {
      setMessageType('error');
      setMessage(updateResponse.error || updateResponse.message);
    }
  }

  return (
    <div>
      <h3>Preferences</h3>

      {message && (
        <div style={{
          backgroundColor: messageType === 'success' ? '#d4edda' : '#f8d7da',
          color: messageType === 'success' ? '#155724' : '#721c24',
          padding: '0.5rem',
          borderRadius: '4px',
          marginBottom: '1rem',
          fontSize: '0.9rem'
        }}>
          {messageType === 'success' ? '✅' : '❌'} {message}
        </div>
      )}

      <div style={{ display: 'flex', gap: '1rem' }}>
        <button
          onClick={() => handleThemeChange('light')}
          disabled={isLoading}
        >
          ☀️ Light
        </button>
        <button
          onClick={() => handleThemeChange('dark')}
          disabled={isLoading}
        >
          🌙 Dark
        </button>
      </div>
    </div>
  );
}

// ============================================================================
// Advanced: Detailed Response Handling
// ============================================================================

export function AdvancedLoginExample() {
  const { login } = useAuth();
  const [status, setStatus] = useState<{
    type: 'idle' | 'loading' | 'success' | 'error';
    message: string;
    user?: any;
  }>({ type: 'idle', message: '' });

  async function handleLogin(email: string, password: string) {
    setStatus({ type: 'loading', message: 'Logging in...' });

    const response = await login({ email, password });

    // response tipi: LoginResponse
    // {
    //   success: boolean;
    //   message: string;
    //   user?: SessionUser;
    //   data?: SessionData;
    //   error?: string;
    // }

    if (response.success) {
      setStatus({
        type: 'success',
        message: response.message,
        user: response.user
      });
    } else {
      setStatus({
        type: 'error',
        message: response.error || response.message
      });
    }
  }

  return (
    <div>
      <h2>Advanced Login</h2>

      <div style={{
        padding: '1rem',
        backgroundColor: status.type === 'success' ? '#d4edda' :
                        status.type === 'error' ? '#f8d7da' :
                        status.type === 'loading' ? '#d1ecf1' : '#f5f5f5',
        borderRadius: '4px',
        marginBottom: '1rem'
      }}>
        <p><strong>Status:</strong> {status.type}</p>
        <p><strong>Message:</strong> {status.message}</p>
        {status.user && (
          <p><strong>User:</strong> {status.user.email}</p>
        )}
      </div>

      <button onClick={() => handleLogin('user@example.com', 'password')}>
        Test Login
      </button>
    </div>
  );
}
