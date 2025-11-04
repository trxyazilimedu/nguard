/**
 * Nguard - Client-side hooks and components
 */

'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Session, SessionUser, SessionData } from './types';
import { getCookieClient, clearCookieClient, setCookieClient } from './cookies';

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
  updateSession: (user: SessionUser, data?: SessionData) => Promise<any>;
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
          // Fallback: try to get from cookie
          const token = getCookieClient(cookieName);
          if (token) {
            // Try to decode token (basic implementation)
            try {
              const base64Url = token.split('.')[1];
              const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
              const jsonPayload = decodeURIComponent(
                atob(base64)
                  .split('')
                  .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                  .join('')
              );
              const payload = JSON.parse(jsonPayload);
              loadedSession = {
                user: payload.user,
                expires: payload.exp * 1000,
                data: payload.data,
              };
            } catch (e) {
              // Token decode failed, session will be null
            }
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

      // Store token in cookie if provided
      if (sessionData.token) {
        setCookieClient(cookieName, sessionData.token, {
          maxAge: 24 * 60 * 60,
        });
      }

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

  const updateSession = async (user: SessionUser, data?: SessionData): Promise<any> => {
    setIsLoading(true);
    try {
      const updatedSession: Session = {
        user,
        expires: session?.expires || Date.now() + 24 * 60 * 60 * 1000,
        data,
      };

      setSession(updatedSession);
      setStatus('authenticated');
      onSessionChange?.(updatedSession);

      // Return the updated session directly
      return {
        success: true,
        message: 'Session updated successfully',
        session: updatedSession,
      };
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
