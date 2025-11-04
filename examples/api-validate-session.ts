/**
 * Validate Session API Endpoint
 * Check if current JWT is valid
 *
 * GET /api/auth/validate
 * Returns: { valid: boolean, session?: Session, error?: string }
 */

import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    // Get token from cookie
    const token = request.cookies.get('nguard-session')?.value;

    if (!token) {
      return NextResponse.json({
        valid: false,
        error: 'No session found',
      });
    }

    // Validate token
    const session = await nguard.validateSession(`nguard-session=${token}`);

    if (!session) {
      return NextResponse.json({
        valid: false,
        error: 'Invalid or expired session',
      });
    }

    // Check if session is expired
    const now = Date.now();
    if (session.expires && session.expires < now) {
      return NextResponse.json({
        valid: false,
        error: 'Session expired',
      });
    }

    return NextResponse.json({
      valid: true,
      session: {
        user: (session as any).id || (session as any).email,
        expires: session.expires,
        role: (session as any).role,
        permissions: (session as any).permissions,
      },
    });
  } catch (error) {
    console.error('Validation error:', error);
    return NextResponse.json(
      {
        valid: false,
        error: 'Validation failed',
      },
      { status: 500 }
    );
  }
}

/**
 * POST version - For checking validity from body
 */
export async function POST(request: NextRequest) {
  try {
    const { token } = await request.json();

    if (!token) {
      return NextResponse.json({
        valid: false,
        error: 'No token provided',
      });
    }

    // Validate token
    const session = await nguard.validateSession(`nguard-session=${token}`);

    if (!session) {
      return NextResponse.json({
        valid: false,
        error: 'Invalid or expired session',
      });
    }

    // Check if session is expired
    const now = Date.now();
    if (session.expires && session.expires < now) {
      return NextResponse.json({
        valid: false,
        error: 'Session expired',
      });
    }

    return NextResponse.json({
      valid: true,
      session,
    });
  } catch (error) {
    console.error('Validation error:', error);
    return NextResponse.json(
      {
        valid: false,
        error: 'Validation failed',
      },
      { status: 500 }
    );
  }
}
