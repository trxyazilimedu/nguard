/**
 * Example API Route for Updating User Role
 * Location: app/api/auth/update-role/route.ts
 *
 * This example shows how to:
 * 1. Validate the current session
 * 2. Check permissions (only admins can change roles)
 * 3. Send request to backend API to update user role
 * 4. Create a new session with updated data
 * 5. Handle errors from backend
 *
 * NOTE: This route acts as a proxy/middleware between frontend and your backend API
 */

import { nguard } from '@/lib/auth';

// Configure your backend API URL here
const BACKEND_API_URL = process.env.BACKEND_API_URL || 'http://localhost:8080/api';

export async function POST(request: Request) {
  try {
    // Step 1: Extract and validate current session
    const headers = Object.fromEntries(request.headers.entries());
    const currentSession = await nguard.validateSession(headers.cookie);

    if (!currentSession) {
      return Response.json(
        { error: 'Unauthorized - Please login first' },
        { status: 401 }
      );
    }

    // Step 2: Check if user has permission to change roles
    // Only admins should be able to change user roles
    if (currentSession.data?.role !== 'admin') {
      return Response.json(
        { error: 'Forbidden - Only admins can change user roles' },
        { status: 403 }
      );
    }

    // Step 3: Parse request body
    const { userId, newRole } = await request.json();

    // Step 4: Validate input
    if (!userId || !newRole) {
      return Response.json(
        { error: 'Bad Request - userId and newRole are required' },
        { status: 400 }
      );
    }

    // Step 5: Validate new role is in allowed values (client-side check)
    const validRoles = ['user', 'moderator', 'admin'];
    if (!validRoles.includes(newRole)) {
      return Response.json(
        { error: `Invalid role. Must be one of: ${validRoles.join(', ')}` },
        { status: 400 }
      );
    }

    // Step 6: Send request to backend API
    // Include auth token or any headers needed by your backend
    const backendResponse = await fetch(`${BACKEND_API_URL}/users/${userId}/role`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        // If your backend needs auth token, add it here:
        // 'Authorization': `Bearer ${currentSession.token}`,
        // Or if using a different auth mechanism:
        'X-Admin-Id': currentSession.user.id,
      },
      body: JSON.stringify({
        role: newRole,
        updatedBy: currentSession.user.id,
      }),
    });

    // Step 7: Handle backend errors
    if (!backendResponse.ok) {
      const errorData = await backendResponse.json().catch(() => ({ error: 'Unknown error' }));

      console.error('Backend error updating role:', errorData);

      if (backendResponse.status === 404) {
        return Response.json(
          { error: 'User not found' },
          { status: 404 }
        );
      }

      if (backendResponse.status === 403) {
        return Response.json(
          { error: errorData.error || 'Operation not allowed' },
          { status: 403 }
        );
      }

      return Response.json(
        { error: errorData.error || 'Failed to update user role' },
        { status: backendResponse.status }
      );
    }

    // Step 8: Get the updated user data from backend
    const updatedUserData = await backendResponse.json();

    // Step 9: If updating own role, create new session with updated data
    if (userId === currentSession.user.id) {
      const { session, setCookieHeader } = await nguard.createSession(
        {
          id: updatedUserData.user.id,
          email: updatedUserData.user.email,
          name: updatedUserData.user.name,
        },
        {
          role: newRole,
          permissions: updatedUserData.user.permissions || [],
        }
      );

      return Response.json(
        {
          success: true,
          message: 'Role updated successfully',
          user: updatedUserData.user,
          session,
        },
        {
          status: 200,
          headers: { 'Set-Cookie': setCookieHeader },
        }
      );
    }

    // Step 10: Return success response for other users
    return Response.json(
      {
        success: true,
        message: `User role updated to ${newRole}`,
        user: updatedUserData.user,
      },
      { status: 200 }
    );

  } catch (error) {
    console.error('Error updating user role:', error);

    return Response.json(
      {
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? String(error) : undefined,
      },
      { status: 500 }
    );
  }
}
