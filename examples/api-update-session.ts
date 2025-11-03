/**
 * Example API Route for Updating Generic Session Data
 * Location: app/api/auth/update/route.ts
 *
 * This example shows how to:
 * 1. Validate and get current session
 * 2. Send update request to backend API
 * 3. Perform client-side validation
 * 4. Create new session with updated data
 * 5. Handle backend errors gracefully
 *
 * NOTE: This route acts as a proxy/middleware between frontend and your backend API
 */

import { nguard } from '@/lib/auth';

// Configure your backend API URL here
const BACKEND_API_URL = process.env.BACKEND_API_URL || 'http://localhost:8080/api';

interface UpdateSessionRequest {
  theme?: 'light' | 'dark';
  language?: 'en' | 'tr';
  notifications?: boolean;
  twoFactorEnabled?: boolean;
  role?: string; // Should not be allowed here - only via admin routes
}

export async function POST(request: Request) {
  try {
    // Step 1: Extract session from cookie
    const headers = Object.fromEntries(request.headers.entries());
    const currentSession = await nguard.validateSession(headers.cookie);

    if (!currentSession) {
      return Response.json(
        { error: 'Unauthorized - Please login first' },
        { status: 401 }
      );
    }

    // Step 2: Parse request body
    const updateData: UpdateSessionRequest = await request.json();

    // Step 3: Security - Remove dangerous fields
    // Users should not be able to change their own role via this endpoint
    if (updateData.role) {
      delete updateData.role;
      console.warn(`User ${currentSession.user.id} attempted to change role via update endpoint`);
    }

    // Step 4: Validate theme value
    if (updateData.theme && !['light', 'dark'].includes(updateData.theme)) {
      return Response.json(
        { error: 'Invalid theme. Must be "light" or "dark"' },
        { status: 400 }
      );
    }

    // Step 5: Validate language value
    if (updateData.language && !['en', 'tr'].includes(updateData.language)) {
      return Response.json(
        { error: 'Invalid language. Must be "en" or "tr"' },
        { status: 400 }
      );
    }

    // Step 6: Validate notifications is boolean
    if (updateData.notifications !== undefined && typeof updateData.notifications !== 'boolean') {
      return Response.json(
        { error: 'Invalid notifications. Must be boolean' },
        { status: 400 }
      );
    }

    // Step 7: Send request to backend API to update preferences
    const backendResponse = await fetch(`${BACKEND_API_URL}/users/${currentSession.user.id}/preferences`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        // Include authentication headers your backend expects:
        // 'Authorization': `Bearer ${currentSession.token}`,
        'X-User-Id': currentSession.user.id,
      },
      body: JSON.stringify({
        theme: updateData.theme,
        language: updateData.language,
        notifications: updateData.notifications,
        twoFactorEnabled: updateData.twoFactorEnabled,
      }),
    });

    // Step 8: Handle backend errors
    if (!backendResponse.ok) {
      const errorData = await backendResponse.json().catch(() => ({ error: 'Unknown error' }));

      console.error('Backend error updating preferences:', errorData);

      return Response.json(
        { error: errorData.error || 'Failed to update preferences' },
        { status: backendResponse.status }
      );
    }

    // Step 9: Get the updated user data from backend
    const backendData = await backendResponse.json();

    // Step 10: Build new session data with all updates
    const newSessionData = {
      role: currentSession.data?.role,
      permissions: currentSession.data?.permissions || [],
      theme: updateData.theme || currentSession.data?.theme,
      language: updateData.language || currentSession.data?.language,
      notifications: updateData.notifications ?? currentSession.data?.notifications,
      twoFactorEnabled: updateData.twoFactorEnabled ?? currentSession.data?.twoFactorEnabled,
      lastUpdated: new Date().toISOString(),
    };

    // Step 11: Create new session with updated data
    const { session, token, setCookieHeader } = await nguard.createSession(
      {
        id: currentSession.user.id,
        email: currentSession.user.email,
        name: currentSession.user.name,
      },
      newSessionData
    );

    // Step 12: Return updated session
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
        },
      }
    );

  } catch (error) {
    console.error('Error updating session:', error);

    // Return generic error in production, detailed in development
    if (error instanceof SyntaxError) {
      return Response.json(
        { error: 'Invalid request body' },
        { status: 400 }
      );
    }

    return Response.json(
      {
        error: 'Failed to update session',
        message: process.env.NODE_ENV === 'development' ? String(error) : undefined,
      },
      { status: 500 }
    );
  }
}
