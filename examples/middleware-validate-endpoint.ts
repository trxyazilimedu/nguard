/**
 * Middleware for /api/auth/validate endpoint
 * Validates current session without requiring authentication
 * Can be called from public clients to check session validity
 */

import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';
import { Session } from 'nguard';

/**
 * Simple validation response format
 */
export interface ValidationResponse {
  valid: boolean;
  session?: {
    id?: string;
    email?: string;
    role?: string;
    permissions?: string[];
    expires?: number;
  };
  error?: string;
  expiresIn?: number; // Milliseconds until expiration
}

/**
 * GET /api/auth/validate
 * No body required - reads session from cookie
 */
export async function GET(request: NextRequest): Promise<NextResponse<ValidationResponse>> {
  try {
    // Get cookie string from request
    const cookieString = request.headers.get('cookie') || '';

    // Validate session from cookie
    const session = await nguard.validateSession(cookieString);

    // No session found
    if (!session) {
      return NextResponse.json<ValidationResponse>(
        {
          valid: false,
          error: 'No valid session found',
        },
        { status: 200 } // Always 200 for validation endpoint
      );
    }

    // Check expiration
    const now = Date.now();
    const expiresAt = session.expires || 0;

    if (expiresAt < now) {
      return NextResponse.json<ValidationResponse>(
        {
          valid: false,
          error: 'Session expired',
          expiresIn: expiresAt - now, // Negative number
        },
        { status: 200 }
      );
    }

    // Session is valid
    const expiresIn = expiresAt - now;

    return NextResponse.json<ValidationResponse>(
      {
        valid: true,
        session: {
          id: (session as any).id,
          email: (session as any).email,
          role: (session as any).role,
          permissions: (session as any).permissions,
          expires: expiresAt,
        },
        expiresIn,
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('[Validate] Error:', error);

    return NextResponse.json<ValidationResponse>(
      {
        valid: false,
        error: 'Validation failed',
      },
      { status: 200 } // Still 200 even on error for validation endpoint
    );
  }
}

/**
 * POST /api/auth/validate
 * For validating a token sent in the request body
 * Useful for cross-origin requests
 */
export async function POST(request: NextRequest): Promise<NextResponse<ValidationResponse>> {
  try {
    const body = await request.json() as { token?: string };
    const token = body.token;

    if (!token) {
      return NextResponse.json<ValidationResponse>(
        {
          valid: false,
          error: 'No token provided',
        },
        { status: 200 }
      );
    }

    // Validate the provided token
    // Token format: "nguard-session=<jwt>"
    const cookieString = `nguard-session=${token}`;
    const session = await nguard.validateSession(cookieString);

    if (!session) {
      return NextResponse.json<ValidationResponse>(
        {
          valid: false,
          error: 'Invalid token',
        },
        { status: 200 }
      );
    }

    // Check expiration
    const now = Date.now();
    const expiresAt = session.expires || 0;

    if (expiresAt < now) {
      return NextResponse.json<ValidationResponse>(
        {
          valid: false,
          error: 'Token expired',
          expiresIn: expiresAt - now,
        },
        { status: 200 }
      );
    }

    const expiresIn = expiresAt - now;

    return NextResponse.json<ValidationResponse>(
      {
        valid: true,
        session: {
          id: (session as any).id,
          email: (session as any).email,
          role: (session as any).role,
          permissions: (session as any).permissions,
          expires: expiresAt,
        },
        expiresIn,
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('[Validate POST] Error:', error);

    return NextResponse.json<ValidationResponse>(
      {
        valid: false,
        error: 'Validation failed',
      },
      { status: 200 }
    );
  }
}

/**
 * HEAD /api/auth/validate
 * Quick validation without response body
 * Returns 200 if valid, 401 if invalid
 */
export async function HEAD(request: NextRequest): Promise<NextResponse> {
  try {
    const cookieString = request.headers.get('cookie') || '';
    const session = await nguard.validateSession(cookieString);

    if (!session) {
      return new NextResponse(null, { status: 401 });
    }

    const now = Date.now();
    if (session.expires && session.expires < now) {
      return new NextResponse(null, { status: 401 });
    }

    return new NextResponse(null, { status: 200 });
  } catch {
    return new NextResponse(null, { status: 401 });
  }
}
