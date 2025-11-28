/**
 * Nguard - Cookie utilities for server and client side
 */

import { SessionOptions } from './types';

const DEFAULT_COOKIE_NAME = 'nguard-session';
const DEFAULT_MAX_AGE = 24 * 60 * 60; // 24 hours in seconds

/**
 * Parse cookie string from request headers
 * Security: Handles malformed cookies gracefully to prevent DoS
 */
export function parseCookies(cookieString?: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  if (!cookieString) return cookies;

  cookieString.split(';').forEach((cookie) => {
    const [name, value] = cookie.split('=');
    if (name && value) {
      try {
        // SECURITY: Wrap decode in try-catch to prevent DoS from malformed cookies
        cookies[decodeURIComponent(name.trim())] = decodeURIComponent(value.trim());
      } catch (error) {
        // Silently ignore malformed cookies
        // Don't log to prevent log flooding attacks
      }
    }
  });

  return cookies;
}

/**
 * Get a specific cookie value from cookie string
 */
export function getCookie(name: string, cookieString?: string): string | null {
  const cookies = parseCookies(cookieString);
  return cookies[name] || null;
}

/**
 * Format cookie string for Set-Cookie header
 * Security: Always sets HttpOnly to prevent XSS attacks
 */
export function formatSetCookie(
  name: string,
  value: string,
  options: SessionOptions = {}
): string {
  const {
    maxAge = DEFAULT_MAX_AGE,
    secure = true,
    sameSite = 'Lax',
  } = options;

  let cookieString = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;

  if (maxAge) {
    cookieString += `; Max-Age=${maxAge}`;
    const expiresDate = new Date();
    expiresDate.setSeconds(expiresDate.getSeconds() + maxAge);
    cookieString += `; Expires=${expiresDate.toUTCString()}`;
  }

  cookieString += `; Path=/`;
  cookieString += `; SameSite=${sameSite}`;

  if (secure) {
    cookieString += '; Secure';
  }

  // SECURITY: HttpOnly prevents JavaScript access to cookies (XSS protection)
  cookieString += '; HttpOnly';

  return cookieString;
}

/**
 * Format clear cookie string
 */
export function formatClearCookie(name: string): string {
  return `${encodeURIComponent(name)}=; Max-Age=0; Path=/; SameSite=Lax`;
}

/**
 * Client-side cookie setter (for use in browser)
 * Security: Automatically sets Secure flag on HTTPS connections
 */
export function setCookieClient(
  name: string,
  value: string,
  options: SessionOptions = {}
): void {
  if (typeof document === 'undefined') {
    console.warn('setCookieClient is for client-side use only');
    return;
  }

  const { maxAge = DEFAULT_MAX_AGE, sameSite = 'Lax', secure = true } = options;

  let cookieString = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;

  if (maxAge) {
    cookieString += `; Max-Age=${maxAge}`;
  }

  cookieString += `; Path=/`;
  cookieString += `; SameSite=${sameSite}`;

  // SECURITY: Add Secure flag on HTTPS connections
  // Note: We cannot set HttpOnly from client-side JavaScript
  if (secure && typeof window !== 'undefined' && window.location.protocol === 'https:') {
    cookieString += '; Secure';
  }

  document.cookie = cookieString;
}

/**
 * Client-side cookie getter (for use in browser)
 */
export function getCookieClient(name: string): string | null {
  if (typeof document === 'undefined') {
    console.warn('getCookieClient is for client-side use only');
    return null;
  }

  return getCookie(name, document.cookie);
}

/**
 * Client-side cookie clearer (for use in browser)
 */
export function clearCookieClient(name: string): void {
  if (typeof document === 'undefined') {
    console.warn('clearCookieClient is for client-side use only');
    return;
  }

  setCookieClient(name, '', { maxAge: 0 });
}
