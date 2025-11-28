/**
 * Example API Route for Updating Session Data
 * Location: app/api/auth/update/route.ts
 *
 * This example shows how to:
 * 1. Get current session from cookie
 * 2. Validate and whitelist allowed fields
 * 3. Update session with partial data (with security controls)
 * 4. Automatically update cookie with new token
 * 5. Add security headers
 * 6. Handle errors gracefully
 *
 * SECURITY FEATURES:
 * - Field whitelisting (only allowed fields can be updated)
 * - Input validation
 * - Security headers (XSS, Clickjacking protection)
 * - SameSite cookie protection (built-in CSRF protection)
 * - Server-side sanitization (built into nguard.updateSession)
 */

import { nguard } from '@/lib/auth';
import { Session } from 'nguard/types';

// Configure your backend API URL here (optional)
const BACKEND_API_URL = process.env.BACKEND_API_URL || 'http://localhost:8080/api';

// IMPORTANT: Define a strict whitelist of allowed fields
// Only these fields can be updated via this endpoint
interface AllowedUserUpdates {
  name?: string;
  email?: string;
  avatar?: string;
}

interface AllowedDataUpdates {
  theme?: 'light' | 'dark';
  language?: 'en' | 'tr' | 'fr' | 'de';
  notifications?: boolean;
  emailNotifications?: boolean;
  timezone?: string;
}

interface AllowedCustomFields {
  customField1?: string;
  customField2?: number;
  lastActivity?: string;
}

// Combined allowed fields
interface UpdateSessionRequest {
  user?: AllowedUserUpdates;
  data?: AllowedDataUpdates;
  // Custom session fields (whitelist these!)
  customField1?: string;
  customField2?: number;
  lastActivity?: string;
}

// Helper: Validate and sanitize updates against whitelist
function validateAndWhitelist(updates: any): UpdateSessionRequest {
  const whitelisted: UpdateSessionRequest = {};

  // Whitelist user fields
  if (updates.user && typeof updates.user === 'object') {
    const safeUser: AllowedUserUpdates = {};

    if (typeof updates.user.name === 'string') {
      safeUser.name = updates.user.name;
    }
    if (typeof updates.user.email === 'string') {
      safeUser.email = updates.user.email;
    }
    if (typeof updates.user.avatar === 'string') {
      safeUser.avatar = updates.user.avatar;
    }

    if (Object.keys(safeUser).length > 0) {
      whitelisted.user = safeUser;
    }
  }

  // Whitelist data fields
  if (updates.data && typeof updates.data === 'object') {
    const safeData: AllowedDataUpdates = {};

    if (updates.data.theme === 'light' || updates.data.theme === 'dark') {
      safeData.theme = updates.data.theme;
    }
    if (['en', 'tr', 'fr', 'de'].includes(updates.data.language)) {
      safeData.language = updates.data.language;
    }
    if (typeof updates.data.notifications === 'boolean') {
      safeData.notifications = updates.data.notifications;
    }
    if (typeof updates.data.emailNotifications === 'boolean') {
      safeData.emailNotifications = updates.data.emailNotifications;
    }
    if (typeof updates.data.timezone === 'string') {
      safeData.timezone = updates.data.timezone;
    }

    if (Object.keys(safeData).length > 0) {
      whitelisted.data = safeData;
    }
  }

  // Whitelist custom fields
  if (typeof updates.customField1 === 'string') {
    whitelisted.customField1 = updates.customField1;
  }
  if (typeof updates.customField2 === 'number') {
    whitelisted.customField2 = updates.customField2;
  }
  if (typeof updates.lastActivity === 'string') {
    whitelisted.lastActivity = updates.lastActivity;
  }

  return whitelisted;
}

export async function POST(request: Request) {
  try {
    // Step 1: Parse request body
    const rawUpdates = await request.json();

    // Step 2: Validate and whitelist allowed fields only
    // IMPORTANT: This prevents users from updating sensitive fields like role, permissions, etc.
    const updates = validateAndWhitelist(rawUpdates);

    // Check if any valid fields were provided
    if (Object.keys(updates).length === 0) {
      return Response.json(
        { error: 'No valid fields to update' },
        { status: 400 }
      );
    }

    // Step 3: Additional validation for specific fields
    if (updates.user?.email) {
      // Simple email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(updates.user.email)) {
        return Response.json(
          { error: 'Invalid email format' },
          { status: 400 }
        );
      }
    }

    if (updates.user?.name) {
      // Name length validation
      if (updates.user.name.length < 2 || updates.user.name.length > 100) {
        return Response.json(
          { error: 'Name must be between 2 and 100 characters' },
          { status: 400 }
        );
      }
    }

    // Step 4: Get cookie string from headers
    const headers = Object.fromEntries(request.headers.entries());
    const cookieString = headers.cookie;

    // Step 5: Optional - Sync with backend database
    // Uncomment if you need to persist changes to a database
    /*
    const currentSession = await nguard.validateSession(cookieString);
    if (currentSession) {
      await fetch(`${BACKEND_API_URL}/users/${currentSession.user.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Id': currentSession.user.id,
        },
        body: JSON.stringify(updates),
      });
    }
    */

    // Step 6: Update session with whitelisted data
    // Server-side security (in nguard.updateSession):
    // - Sanitizes all input (XSS protection)
    // - Removes protected fields (role, permissions, sessionId, etc.)
    // - Enforces user.id immutability
    // - Rate limiting (if enabled)
    // - Payload size limit (10KB max)
    // - Old session invalidation (if blacklist enabled)
    const { session, token, setCookieHeader } = await nguard.updateSession(
      cookieString,
      updates
    );

    // Step 7: Return success response with security headers
    return Response.json(
      {
        success: true,
        message: 'Session updated successfully',
        session,
        token,
      },
      {
        status: 200,
        headers: {
          'Set-Cookie': setCookieHeader,
          'Content-Type': 'application/json',
          // Security headers
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
          'Content-Security-Policy': "default-src 'self'",
        },
      }
    );

  } catch (error) {
    console.error('Error updating session:', error);

    // Determine appropriate status code and message
    let statusCode = 500;
    let errorMessage = 'Failed to update session';

    if (error instanceof SyntaxError) {
      statusCode = 400;
      errorMessage = 'Invalid request body';
    } else if (error instanceof Error) {
      if (error.message === 'No active session found') {
        statusCode = 401;
        errorMessage = 'Unauthorized - Please login first';
      } else if (error.message.includes('too large')) {
        statusCode = 413;
        errorMessage = 'Request payload too large';
      } else if (error.message.includes('Too many')) {
        statusCode = 429;
        errorMessage = 'Too many requests. Please try again later.';
      }
    }

    // Return error response with security headers
    return Response.json(
      {
        success: false,
        error: errorMessage,
        // Only show detailed error in development
        details: process.env.NODE_ENV === 'development' ? String(error) : undefined,
      },
      {
        status: statusCode,
        headers: {
          'Content-Type': 'application/json',
          'X-Content-Type-Options': 'nosniff',
        },
      }
    );
  }
}
