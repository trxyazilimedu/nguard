#!/usr/bin/env node

/**
 * Nguard Update CLI
 * Detects and creates missing files in existing Nguard installations
 * Safe updates - only creates missing files, never overwrites existing ones
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const question = (query: string): Promise<string> => {
  return new Promise((resolve) => {
    rl.question(query, resolve);
  });
};

const confirm = (query: string): Promise<boolean> => {
  return new Promise((resolve) => {
    rl.question(query + ' (y/n): ', (answer) => {
      resolve(answer.toLowerCase() === 'y');
    });
  });
};

interface ProjectStatus {
  hasNguard: boolean;
  libAuthExists: boolean;
  useTypeScript: boolean;
  appDir: string;
  existingRoutes: string[];
  missingRoutes: string[];
  cookieName: string;
}

const AVAILABLE_ROUTES = [
  { name: 'login', path: '/api/auth/login', recommended: true },
  { name: 'logout', path: '/api/auth/logout', recommended: true },
  { name: 'validate', path: '/api/auth/validate', recommended: true },
  { name: 'update', path: '/api/auth/update', recommended: true, new: true },
  { name: 'refresh', path: '/api/auth/refresh', recommended: false },
];

async function main() {
  console.log('\n╔═══════════════════════════════════════════╗');
  console.log('║        Nguard Update Utility v2.0        ║');
  console.log('║   Safe updates for existing projects     ║');
  console.log('╚═══════════════════════════════════════════╝\n');

  try {
    // Step 1: Analyze project
    console.log('🔍 Analyzing your project...\n');
    const status = await analyzeProject();

    if (!status.hasNguard) {
      console.log('❌ Nguard is not installed in this project.');
      console.log('   Run `npx nguard-setup` to install Nguard first.\n');
      rl.close();
      return;
    }

    // Step 2: Show status
    displayProjectStatus(status);

    // Step 3: Check if lib/auth needs to be created
    let createLibAuth = false;
    if (!status.libAuthExists) {
      console.log('⚠️  lib/auth file is missing!\n');
      createLibAuth = await confirm('Create lib/auth file?');

      if (createLibAuth) {
        await createAuthFile(status);
        console.log('');
      }
    }

    // Step 4: Check if any route updates are needed
    if (status.missingRoutes.length === 0) {
      if (!createLibAuth) {
        console.log('\n✅ Your project is up to date! All API routes exist.\n');
      }
      rl.close();
      return;
    }

    // Step 5: Ask user which missing files to create
    console.log('\n📦 MISSING FILES DETECTED\n');
    const filesToCreate = await selectFilesToCreate(status);

    if (filesToCreate.length === 0) {
      console.log('\n✅ No files selected. Update cancelled.\n');
      rl.close();
      return;
    }

    // Step 6: Confirm before creating files
    console.log('\n📋 FILES TO BE CREATED:\n');
    filesToCreate.forEach(route => {
      const routePath = `${status.appDir}/api/auth/${route}/route.${status.useTypeScript ? 'ts' : 'js'}`;
      console.log(`  ✓ ${routePath}`);
    });

    const proceed = await confirm('\nProceed with file creation?');
    if (!proceed) {
      console.log('\n✅ Update cancelled.\n');
      rl.close();
      return;
    }

    // Step 7: Create missing files
    await createMissingFiles(status, filesToCreate);

    console.log('\n✅ Update completed successfully!\n');
    printNextSteps(filesToCreate);

  } catch (error) {
    console.error('\n❌ Update failed:', error);
  } finally {
    rl.close();
  }
}

async function analyzeProject(): Promise<ProjectStatus> {
  const projectRoot = process.cwd();

  // Check if Nguard is installed
  const packageJsonPath = path.join(projectRoot, 'package.json');
  let hasNguard = false;

  if (fs.existsSync(packageJsonPath)) {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    hasNguard = !!(packageJson.dependencies?.nguard || packageJson.devDependencies?.nguard);
  }

  // Check for lib/auth.ts or lib/auth.js
  const libAuthTs = path.join(projectRoot, 'lib', 'auth.ts');
  const libAuthJs = path.join(projectRoot, 'lib', 'auth.js');
  const libAuthExists = fs.existsSync(libAuthTs) || fs.existsSync(libAuthJs);
  const useTypeScript = fs.existsSync(libAuthTs);

  // Detect app directory
  let appDir = 'app';
  if (fs.existsSync(path.join(projectRoot, 'src', 'app'))) {
    appDir = 'src/app';
  }

  // Check existing API routes
  const apiAuthDir = path.join(projectRoot, appDir, 'api', 'auth');
  const existingRoutes: string[] = [];

  if (fs.existsSync(apiAuthDir)) {
    const dirs = fs.readdirSync(apiAuthDir);
    for (const dir of dirs) {
      const routePath = path.join(apiAuthDir, dir);
      if (fs.statSync(routePath).isDirectory()) {
        const routeFile = path.join(routePath, `route.${useTypeScript ? 'ts' : 'js'}`);
        if (fs.existsSync(routeFile)) {
          existingRoutes.push(dir);
        }
      }
    }
  }

  // Determine missing routes
  const allRouteNames = AVAILABLE_ROUTES.map(r => r.name);
  const missingRoutes = allRouteNames.filter(name => !existingRoutes.includes(name));

  // Try to detect cookie name from lib/auth file
  let cookieName = 'nguard-session';
  if (libAuthExists) {
    const authFile = useTypeScript ? libAuthTs : libAuthJs;
    const content = fs.readFileSync(authFile, 'utf-8');
    const match = content.match(/cookieName:\s*['"]([^'"]+)['"]/);
    if (match) {
      cookieName = match[1];
    }
  }

  return {
    hasNguard,
    libAuthExists,
    useTypeScript,
    appDir,
    existingRoutes,
    missingRoutes,
    cookieName,
  };
}

function displayProjectStatus(status: ProjectStatus) {
  console.log('📊 PROJECT STATUS\n');
  console.log(`  ✓ Nguard installed: ${status.hasNguard ? 'Yes' : 'No'}`);
  console.log(`  ✓ lib/auth exists: ${status.libAuthExists ? 'Yes' : 'No'}`);
  console.log(`  ✓ TypeScript: ${status.useTypeScript ? 'Yes' : 'No'}`);
  console.log(`  ✓ App directory: ${status.appDir}`);
  console.log(`  ✓ Cookie name: ${status.cookieName}\n`);

  console.log('📁 API ROUTES STATUS\n');

  // Show existing routes
  if (status.existingRoutes.length > 0) {
    console.log('  ✅ Existing routes:');
    status.existingRoutes.forEach(route => {
      const routeInfo = AVAILABLE_ROUTES.find(r => r.name === route);
      console.log(`     ✓ ${route} ${routeInfo?.path}`);
    });
    console.log('');
  }

  // Show missing routes
  if (status.missingRoutes.length > 0) {
    console.log('  ⚠️  Missing routes:');
    status.missingRoutes.forEach(route => {
      const routeInfo = AVAILABLE_ROUTES.find(r => r.name === route);
      const badge = routeInfo?.new ? ' [NEW in v2.0]' : '';
      console.log(`     ❌ ${route} ${routeInfo?.path}${badge}`);
    });
  }
}

async function selectFilesToCreate(status: ProjectStatus): Promise<string[]> {
  const selected: string[] = [];

  for (const routeName of status.missingRoutes) {
    const routeInfo = AVAILABLE_ROUTES.find(r => r.name === routeName);
    if (!routeInfo) continue;

    const badge = routeInfo.new ? ' [NEW - RECOMMENDED]' : routeInfo.recommended ? ' [RECOMMENDED]' : '';
    const create = await confirm(`Create ${routeInfo.path}?${badge}`);

    if (create) {
      selected.push(routeName);
    }
  }

  return selected;
}

async function createAuthFile(status: ProjectStatus) {
  console.log('🔧 CREATING lib/auth FILE\n');

  const projectRoot = process.cwd();
  const ext = status.useTypeScript ? 'ts' : 'js';
  const libDir = path.join(projectRoot, 'lib');
  const authFile = path.join(libDir, `auth.${ext}`);

  // Create lib directory if it doesn't exist
  if (!fs.existsSync(libDir)) {
    fs.mkdirSync(libDir, { recursive: true });
  }

  const content = generateAuthFileContent(status);
  fs.writeFileSync(authFile, content);
  console.log(`  ✓ Created ${authFile}\n`);
}

function generateAuthFileContent(status: ProjectStatus): string {
  const isTs = status.useTypeScript;
  const typeAnnotation = isTs ? ': Promise<Session | null>' : '';

  return `/**
 * Nguard Authentication Setup
 * Generated by Nguard Update CLI
 */

import { initializeServer } from 'nguard/server';
import { headers } from 'next/headers';
${isTs ? "import { Session } from 'nguard';" : ''}

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET || '',
  secure: process.env.NODE_ENV === 'production',
  cookieName: '${status.cookieName}',
});

/**
 * Get current session in Server Components
 * Usage: const session = await auth();
 */
export async function auth()${typeAnnotation} {
  try {
    const headersList = await headers();
    const cookie = headersList.get('cookie');
    if (!cookie) return null;

    return await nguard.validateSession(cookie);
  } catch (error) {
    return null;
  }
}

/**
 * Create a new session
 */
export const createSession = (sessionData${isTs ? ': any' : ''}) =>
  nguard.createSession(sessionData);

/**
 * Clear the session
 */
export const clearSession = () => nguard.clearSession();

/**
 * Update existing session
 * @param cookieString - Cookie string from request headers
 * @param updates - Partial session updates
 */
export const updateSession = (cookieString${isTs ? ': string | null | undefined' : ''}, updates${isTs ? ': any' : ''}) =>
  nguard.updateSession(cookieString, updates);

/**
 * Validate a session
 */
export const validateSession = (cookieString${isTs ? ': string' : ''}) =>
  nguard.validateSession(cookieString);
`;
}

async function createMissingFiles(status: ProjectStatus, routes: string[]) {
  console.log('\n🔧 CREATING FILES\n');

  const projectRoot = process.cwd();
  const apiAuthDir = path.join(projectRoot, status.appDir, 'api', 'auth');
  const ext = status.useTypeScript ? 'ts' : 'js';

  // Ensure api/auth directory exists
  if (!fs.existsSync(apiAuthDir)) {
    fs.mkdirSync(apiAuthDir, { recursive: true });
  }

  for (const route of routes) {
    const routeDir = path.join(apiAuthDir, route);
    const routeFile = path.join(routeDir, `route.${ext}`);

    // Create route directory
    if (!fs.existsSync(routeDir)) {
      fs.mkdirSync(routeDir, { recursive: true });
    }

    // Generate route content
    const content = generateRouteContent(route, status);

    // Write file
    fs.writeFileSync(routeFile, content);
    console.log(`  ✓ Created ${routeFile}`);
  }
}

function generateRouteContent(route: string, status: ProjectStatus): string {
  const isTs = status.useTypeScript;

  const routes: Record<string, string> = {
    login: `import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

const BACKEND_API_URL = process.env.BACKEND_API_URL || '';

export async function POST(request${isTs ? ': NextRequest' : ''}) {
  try {
    const { email, password } = await request.json();

    // Step 1: Authenticate with your backend
    const backendResponse = await fetch(\`\${BACKEND_API_URL}/auth/login\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!backendResponse.ok) {
      throw new Error('Authentication failed');
    }

    const backendData = await backendResponse.json();

    // Step 2: Create session with Nguard
    const { session, setCookieHeader } = await nguard.createSession({
      ...backendData,
      expires: Date.now() + 24 * 60 * 60 * 1000,
    });

    return NextResponse.json({ session }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Login failed' },
      { status: 401 }
    );
  }
}
`,

    logout: `import { nguard } from '@/lib/auth';
import { NextResponse } from 'next/server';

export async function POST() {
  try {
    const clearHeader = nguard.clearSession();

    return NextResponse.json({ ok: true }, {
      headers: { 'Set-Cookie': clearHeader }
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Logout failed' },
      { status: 500 }
    );
  }
}
`,

    validate: `import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request${isTs ? ': NextRequest' : ''}) {
  try {
    const cookieString = request.headers.get('cookie') || '';
    const session = await nguard.validateSession(cookieString);

    if (!session) {
      return NextResponse.json({
        valid: false,
        error: 'No valid session',
      });
    }

    const now = Date.now();
    if (session.expires && session.expires < now) {
      return NextResponse.json({
        valid: false,
        error: 'Session expired',
        expiresIn: session.expires - now,
      });
    }

    return NextResponse.json({
      valid: true,
      session,
      expiresIn: session.expires - now,
    });
  } catch (error) {
    return NextResponse.json(
      { valid: false, error: 'Validation failed' },
      { status: 500 }
    );
  }
}
`,

    update: `import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request${isTs ? ': NextRequest' : ''}) {
  try {
    // Get updates from request body
    const updates = await request.json();

    // Get current session from cookie
    const cookieString = request.headers.get('cookie');

    // Update session (handles security automatically)
    const { session, token, setCookieHeader } = await nguard.updateSession(
      cookieString,
      updates
    );

    // Return updated session with new cookie
    return NextResponse.json(
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

    if (error instanceof Error && error.message === 'No active session found') {
      return NextResponse.json(
        { error: 'Unauthorized - Please login first' },
        { status: 401 }
      );
    }

    return NextResponse.json(
      { error: 'Failed to update session' },
      { status: 500 }
    );
  }
}
`,

    refresh: `import { nguard } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request${isTs ? ': NextRequest' : ''}) {
  try {
    const cookieString = request.headers.get('cookie') || '';
    const session = await nguard.validateSession(cookieString);

    if (!session) {
      return NextResponse.json(
        { error: 'No session to refresh' },
        { status: 401 }
      );
    }

    // Extend session expiration
    const { setCookieHeader } = await nguard.createSession({
      ...session,
      expires: Date.now() + 24 * 60 * 60 * 1000,
    });

    return NextResponse.json({ ok: true }, {
      headers: { 'Set-Cookie': setCookieHeader }
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Refresh failed' },
      { status: 500 }
    );
  }
}
`,
  };

  return routes[route] || '';
}

function printNextSteps(createdRoutes: string[]) {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📝 NEXT STEPS\n');

  if (createdRoutes.includes('update')) {
    console.log('🎉 NEW: /api/auth/update endpoint created!\n');
    console.log('This endpoint allows safe session updates.');
    console.log('See QUICKSTART-UPDATE.md for usage examples.\n');
  }

  console.log('1. 🔧 Update your backend URL (if needed):');
  console.log('   Edit .env.local');
  console.log('   Set BACKEND_API_URL to your backend URL\n');

  console.log('2. ✅ Test your new endpoints:');
  console.log('   npm run dev');
  console.log('   Visit http://localhost:3000\n');

  if (createdRoutes.includes('update')) {
    console.log('3. 📚 Learn how to use session updates:');
    console.log('   Read: QUICKSTART-UPDATE.md');
    console.log('   Example: examples/api-update-session.ts');
    console.log('   Client usage: examples/components-update-session.tsx\n');
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}

// Run the update
main().catch(console.error);
