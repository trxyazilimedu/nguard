/**
 * Nguard - Client-side hooks and components
 */

'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Session, SessionUser, SessionData } from './types';
import { clearCookieClient } from './cookies';

/**
 * Login callback function type
 * Implement this to handle login with your own backend
 * Should return session data (flexible structure)
 */
export type LoginCallback<T = any> = (credentials: T) => Promise<any>;

/**
 * Logout callback function type
 * Implement this to handle logout with your own backend
 */
export type LogoutCallback = () => Promise<void>;

/**
 * Update session callback function type
 * Implement this to handle session updates with your own backend
 */
export type UpdateSessionCallback = (updates: Partial<Session>) => Promise<any>;

/**
 * Initialize session callback function type
 * Implement this to load session from your backend or storage
 */
export type InitializeSessionCallback = () => Promise<Session | null>;

/**
 * Login response type
 */
export interface LoginResponse {
  success: boolean;
  message: string;
  user?: SessionUser;
  data?: SessionData;
  error?: string;
}

/**
 * Logout response type
 */
export interface LogoutResponse {
  success: boolean;
  message: string;
  error?: string;
}

/**
 * Update session response type
 */
export interface UpdateSessionResponse {
  success: boolean;
  message: string;
  session?: Session;
  error?: string;
}

interface SessionContextType {
  session: Session | null;
  status: 'loading' | 'authenticated' | 'unauthenticated';
  login: <T = any>(credentials: T) => Promise<any>;
  logout: () => Promise<any>;
  updateSession: (updates: Partial<Session>) => Promise<any>;
  isLoading: boolean;
}

const SessionContext = createContext<SessionContextType | undefined>(undefined);

interface SessionProviderProps {
  /**
   * Child components (optional - can be passed as children)
   */
  children?: ReactNode;
  /**
   * Cookie name for storing session
   * @default 'nguard-session'
   */
  cookieName?: string;
  /**
   * Custom login callback
   * If not provided, uses default: POST /api/auth/login
   */
  onLogin?: LoginCallback;
  /**
   * Custom logout callback
   * If not provided, uses default: POST /api/auth/logout
   */
  onLogout?: LogoutCallback;
  /**
   * Custom update session callback
   * If not provided, uses default: POST /api/auth/update
   */
  onUpdateSession?: UpdateSessionCallback;
  /**
   * Custom initialize callback
   * If not provided, tries to decode JWT from cookie
   */
  onInitialize?: InitializeSessionCallback;
  /**
   * Called whenever session changes
   */
  onSessionChange?: (session: Session | null) => void;
}

/**
 * SessionProvider - Wrap your app with this component
 */
export function SessionProvider({
  children,
  cookieName = 'nguard-session',
  onLogin,
  onLogout,
  onUpdateSession,
  onInitialize,
  onSessionChange,
}: SessionProviderProps) {
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState<'loading' | 'authenticated' | 'unauthenticated'>('loading');
  const [isLoading, setIsLoading] = useState(false);

  // Initialize session on mount
  useEffect(() => {
    const initializeSession = async () => {
      setStatus('loading');
      try {
        let loadedSession: Session | null = null;

        // Use custom initialize callback if provided
        if (onInitialize) {
          loadedSession = await onInitialize();
        } else {
          // Since cookies are HttpOnly, we need to validate via server endpoint
          // This is the secure way - cookies are sent automatically with fetch
          try {
            const response = await fetch('/api/auth/validate', {
              method: 'GET',
              credentials: 'include', // Send HttpOnly cookies automatically
            });

            if (response.ok) {
              const data = await response.json();
              if (data.valid && data.session) {
                loadedSession = data.session;
              }
            }
          } catch (e) {
            // Validation endpoint not available or failed
            // This is expected if /api/auth/validate doesn't exist
            // Session will remain null
          }
        }

        setSession(loadedSession || null);
        setStatus(loadedSession ? 'authenticated' : 'unauthenticated');
        onSessionChange?.(loadedSession || null);
      } catch (error) {
        setSession(null);
        setStatus('unauthenticated');
        onSessionChange?.(null);
      }
    };

    initializeSession();
  }, []);

  // Default login handler
  const defaultLogin = async <T = any,>(credentials: T) => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
      credentials: 'include', // Ensure cookies are sent and received
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Login failed');
    }

    const data = await response.json();
    // Return the session data directly from API
    return data.session || data;
  };

  const login = async <T = any,>(credentials: T): Promise<any> => {
    const loginFn = onLogin || defaultLogin;

    setIsLoading(true);
    try {
      const sessionData = await loginFn(credentials);

      // Session data from callback is the session itself
      // Ensure expires is set properly
      const now = Date.now();
      const newSession: Session = {
        ...sessionData,
        expires: sessionData.expires || now + 24 * 60 * 60 * 1000, // Default 24 hours if not provided
      };

      setSession(newSession);
      setStatus('authenticated');

      // NOTE: We don't set cookies client-side because they are HttpOnly
      // The server already sets the cookie via Set-Cookie header
      // Client-side cookie setting would fail anyway due to HttpOnly flag

      onSessionChange?.(newSession);

      // Return API response as-is
      return sessionData;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Login failed';

      // Return error response
      return {
        success: false,
        message: errorMessage,
        error: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  };

  // Default logout handler
  const defaultLogout = async () => {
    const response = await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include', // Ensure cookies are sent
    });

    if (!response.ok) {
      throw new Error('Logout failed');
    }

    return await response.json();
  };

  const logout = async (): Promise<any> => {
    setIsLoading(true);
    try {
      // Use custom logout callback if provided, otherwise use default
      const logoutFn = onLogout || defaultLogout;
      const response = await logoutFn();

      setSession(null);
      setStatus('unauthenticated');
      onSessionChange?.(null);
      clearCookieClient(cookieName);

      // Return API response as-is
      return response;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Logout failed';

      // Return error response but still clear session
      setSession(null);
      setStatus('unauthenticated');
      onSessionChange?.(null);
      clearCookieClient(cookieName);

      return {
        success: false,
        message: errorMessage,
        error: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  };

  // Default update session handler
  const defaultUpdateSession = async (updates: Partial<Session>) => {
    try {
      const response = await fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
        credentials: 'include',
      });

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        // If not JSON (likely 404 HTML page), return null to trigger local-only update
        return null;
      }

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Session update failed');
      }

      return await response.json();
    } catch (error) {
      // If fetch fails (endpoint not found, network error, etc.), return null for local-only update
      if (error instanceof TypeError || (error instanceof Error && error.message.includes('Failed to fetch'))) {
        return null;
      }
      throw error;
    }
  };

  const updateSession = async (updates: Partial<Session>): Promise<any> => {
    setIsLoading(true);
    try {
      let responseData = null;

      // Try to sync with server if callback provided or default endpoint exists
      if (onUpdateSession) {
        responseData = await onUpdateSession(updates);
      } else {
        responseData = await defaultUpdateSession(updates);
      }

      // If server sync successful, use server response
      if (responseData && responseData.session) {
        const updatedSession: Session = responseData.session;

        setSession(updatedSession);
        setStatus('authenticated');

        // NOTE: We don't set cookies client-side because they are HttpOnly
        // The server already updated the cookie via Set-Cookie header

        onSessionChange?.(updatedSession);

        return responseData;
      }

      // If server sync failed or not available, do local-only update
      // This happens when:
      // 1. /api/auth/update endpoint doesn't exist
      // 2. Network error
      // 3. Server returned non-JSON response
      if (session) {
        // IMPORTANT: Local-only updates are temporary and will be lost on page refresh
        // because session cookies are HttpOnly and cannot be updated from client-side JavaScript
        if (process.env.NODE_ENV === 'development') {
          console.warn(
            '[Nguard] Session update is local-only. Changes will be lost on page refresh.\n' +
            'To persist changes, create a /api/auth/update endpoint or provide an onUpdateSession callback.\n' +
            'See: https://github.com/anthropics/nguard/blob/main/examples/api-update-session.ts'
          );
        }

        const updatedSession: Session = {
          ...session,
          ...updates,
          // Deep merge user if provided
          user: updates.user
            ? { ...session.user, ...updates.user }
            : session.user,
          // Deep merge data if provided
          data: updates.data
            ? { ...session.data, ...updates.data }
            : session.data,
        };

        setSession(updatedSession);
        setStatus('authenticated');
        onSessionChange?.(updatedSession);

        return {
          success: true,
          message: 'Session updated locally (server sync not available)',
          session: updatedSession,
          localOnly: true, // Flag to indicate this was local-only update
          warning: 'Changes will be lost on page refresh. Create /api/auth/update endpoint to persist.',
        };
      }

      throw new Error('No active session to update');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to update session';

      // Return error response
      return {
        success: false,
        message: errorMessage,
        error: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <SessionContext.Provider value={{ session, status, login, logout, updateSession, isLoading }}>
      {children}
    </SessionContext.Provider>
  );
}

/**
 * useSession hook - Get current session and auth functions
 */
export function useSession(): SessionContextType {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error('useSession must be used within SessionProvider');
  }
  return context;
}

/**
 * useAuth hook - Simplified auth hook
 */
export function useAuth() {
  const { session, status, login, logout } = useSession();

  return {
    user: session?.user || null,
    isAuthenticated: status === 'authenticated',
    isLoading: status === 'loading',
    login,
    logout,
  };
}

/**
 * useSessionUpdate hook - Update session data
 */
export function useSessionUpdate() {
  const { updateSession, isLoading } = useSession();

  return {
    updateSession,
    isLoading,
  };
}

/**
 * useLogin hook - Login function only
 */
export function useLogin() {
  const { login, isLoading } = useSession();

  return {
    login,
    isLoading,
  };
}

/**
 * useLogout hook - Logout function only
 */
export function useLogout() {
  const { logout, isLoading } = useSession();

  return {
    logout,
    isLoading,
  };
}
