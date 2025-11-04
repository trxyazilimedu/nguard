#!/usr/bin/env node

/**
 * Nguard Setup CLI
 * Automated setup wizard for Next.js projects
 * Generates lib/auth.ts, API routes, and proxy.ts configuration
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

interface SetupConfig {
  projectRoot: string;
  appDir: string;
  useTypeScript: boolean;
  authRoutes: string[];
  cookieName: string;
  environment: string;
}

async function main() {
  console.log('\n╔═══════════════════════════════════════════╗');
  console.log('║        Nguard Setup Wizard v0.3.2        ║');
  console.log('║   Automated Next.js Authentication       ║');
  console.log('╚═══════════════════════════════════════════╝\n');

  // Disclaimer
  console.log('⚠️  DISCLAIMER:');
  console.log('This wizard will automatically create/modify files in your Next.js project.');
  console.log('- Creates lib/auth.ts or lib/auth.js');
  console.log('- Creates API routes under app/api/auth/');
  console.log('- Creates or updates proxy.ts configuration');
  console.log('- Adds environment variables template\n');

  const confirmed = await confirm('Do you want to continue? This action cannot be undone.');

  if (!confirmed) {
    console.log('Setup cancelled.');
    rl.close();
    return;
  }

  // Get user confirmation for responsibility
  const responsibility = await confirm(
    'Do you take full responsibility for these changes and understand the risks?'
  );

  if (!responsibility) {
    console.log('Setup cancelled. You must accept responsibility to continue.');
    rl.close();
    return;
  }

  console.log('\n✅ Setup will proceed. Let\'s configure your project.\n');

  try {
    const config = await gatherConfiguration();
    await executeSetup(config);
    console.log('\n✅ Setup completed successfully!\n');
    printNextSteps(config);
  } catch (error) {
    console.error('\n❌ Setup failed:', error);
  } finally {
    rl.close();
  }
}

async function gatherConfiguration(): Promise<SetupConfig> {
  console.log('📋 PROJECT CONFIGURATION\n');

  const projectRoot = process.cwd();
  console.log(`Project Root: ${projectRoot}\n`);

  const useTypeScript = await confirm('Is this a TypeScript project?');

  const appDir = await question('App directory path (default: app): ');
  const apiAuthDir = appDir || 'app';

  const cookieName = await question('Cookie name for session (default: nguard-session): ');

  const environment = await question('Environment (development/production, default: development): ');

  console.log('\n📦 SELECT AUTH ROUTES TO CREATE\n');
  const authRoutes: string[] = [];

  const routes = [
    { name: 'login', path: '/api/auth/login', default: true },
    { name: 'logout', path: '/api/auth/logout', default: true },
    { name: 'validate', path: '/api/auth/validate', default: true },
    { name: 'refresh', path: '/api/auth/refresh', default: false },
  ];

  for (const route of routes) {
    const create = await confirm(
      `Create ${route.path}? ${route.default ? '(recommended)' : ''}`
    );
    if (create) {
      authRoutes.push(route.name);
    }
  }

  return {
    projectRoot,
    appDir: apiAuthDir || 'app',
    useTypeScript,
    authRoutes,
    cookieName: cookieName || 'nguard-session',
    environment: environment || 'development',
  };
}

async function executeSetup(config: SetupConfig) {
  console.log('\n🔧 EXECUTING SETUP\n');

  // Create lib/auth.ts
  console.log('📄 Creating lib/auth.ts...');
  await createAuthFile(config);

  // Create API routes
  console.log('📁 Creating API routes...');
  await createApiRoutes(config);

  // Create proxy.ts
  console.log('⚙️  Creating proxy.ts configuration...');
  await createProxyConfig(config);

  // Create .env.local template
  console.log('🔑 Creating .env.local template...');
  await createEnvTemplate(config);

  // Create tsconfig.json path alias if needed
  if (config.useTypeScript) {
    console.log('✅ Updating tsconfig.json...');
    await updateTsConfig(config);
  }

  console.log('\n✨ All files created successfully!\n');
}

async function createAuthFile(config: SetupConfig) {
  const ext = config.useTypeScript ? 'ts' : 'js';
  const libDir = path.join(config.projectRoot, 'lib');
  const authFile = path.join(libDir, `auth.${ext}`);

  // Create lib directory if it doesn't exist
  if (!fs.existsSync(libDir)) {
    fs.mkdirSync(libDir, { recursive: true });
  }

  const content = generateAuthFileContent(config);

  fs.writeFileSync(authFile, content);
  console.log(`  ✓ Created ${authFile}`);
}

async function createApiRoutes(config: SetupConfig) {
  const apiAuthDir = path.join(
    config.projectRoot,
    config.appDir,
    'api',
    'auth'
  );

  // Create directories
  if (!fs.existsSync(apiAuthDir)) {
    fs.mkdirSync(apiAuthDir, { recursive: true });
  }

  const ext = config.useTypeScript ? 'ts' : 'js';

  // Create each route
  for (const route of config.authRoutes) {
    const routeDir = path.join(apiAuthDir, route);
    const routeFile = path.join(routeDir, `route.${ext}`);

    if (!fs.existsSync(routeDir)) {
      fs.mkdirSync(routeDir, { recursive: true });
    }

    const content = generateRouteContent(route, config);
    fs.writeFileSync(routeFile, content);
    console.log(`  ✓ Created ${routeFile}`);
  }
}

async function createProxyConfig(config: SetupConfig) {
  const proxyFile = path.join(config.projectRoot, 'proxy.ts');
  const content = generateProxyContent(config);

  fs.writeFileSync(proxyFile, content);
  console.log(`  ✓ Created ${proxyFile}`);
}

async function createEnvTemplate(config: SetupConfig) {
  const envFile = path.join(config.projectRoot, '.env.local.example');
  const content = generateEnvContent(config);

  fs.writeFileSync(envFile, content);
  console.log(`  ✓ Created ${envFile}`);
}

async function updateTsConfig(config: SetupConfig) {
  const tsConfigPath = path.join(config.projectRoot, 'tsconfig.json');

  if (fs.existsSync(tsConfigPath)) {
    const tsConfig = JSON.parse(fs.readFileSync(tsConfigPath, 'utf-8'));

    if (!tsConfig.compilerOptions.paths) {
      tsConfig.compilerOptions.paths = {};
    }

    if (!tsConfig.compilerOptions.paths['@/*']) {
      tsConfig.compilerOptions.paths['@/*'] = ['./*'];
    }

    fs.writeFileSync(tsConfigPath, JSON.stringify(tsConfig, null, 2));
    console.log(`  ✓ Updated ${tsConfigPath}`);
  }
}

function generateAuthFileContent(config: SetupConfig): string {
  const isTs = config.useTypeScript;
  const typeAnnotation = isTs ? ': Promise<Session | null>' : '';

  return `/**
 * Nguard Authentication Setup
 * Generated by Nguard Setup CLI
 */

import { initializeServer } from 'nguard/server';
import { headers } from 'next/headers';
${isTs ? "import { Session } from 'nguard';" : ''}

export const nguard = initializeServer({
  secret: process.env.NGUARD_SECRET || '',
  secure: process.env.NODE_ENV === 'production',
  cookieName: '${config.cookieName}',
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
 */
export const updateSession = (sessionData${isTs ? ': any' : ''}) =>
  nguard.updateSession(sessionData);

/**
 * Validate a session
 */
export const validateSession = (cookieString${isTs ? ': string' : ''}) =>
  nguard.validateSession(cookieString);
`;
}

function generateRouteContent(route: string, config: SetupConfig): string {
  const isTs = config.useTypeScript;

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

function generateProxyContent(config: SetupConfig): string {
  const isTs = config.useTypeScript;

  return `/**
 * Nguard Proxy Configuration
 * Next.js 16+ proxy.ts (replaces middleware.ts)
 * Generated by Nguard Setup CLI
 */

${isTs ? "import { NextRequest, NextResponse } from 'next/server';" : 'import { NextRequest, NextResponse } from \'next/server\';'}
${isTs ? "import { Session } from 'nguard';" : ''}
import { compose, requireAuth, logger } from 'nguard';

/**
 * Proxy function - runs on Node.js runtime
 * This makes the app's network boundary explicit
 */
export async function proxy(request${isTs ? ': NextRequest' : ''})${isTs ? ': Promise<NextResponse>' : ''} {
  const cookieString = request.headers.get('cookie') || '';

  // Get session from cookies
  let session${isTs ? ': Session | null' : ''} = null;
  try {
    if (cookieString) {
      // You would need to validate the session here
      // For now, we'll keep it simple
      session = null;
    }
  } catch (error) {
    session = null;
  }

  // Apply middleware
  const middleware = compose(
    logger({
      onLog: (data) => {
        // Log requests as needed
      },
    })
  );

  const response = await middleware(request, session);

  return response || NextResponse.next();
}

/**
 * Configure which paths proxy should handle
 * Exclude static files, images, API routes, etc.
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!api|_next/static|_next/image|favicon.ico|public).*)',
  ],
};
`;
}

function generateEnvContent(config: SetupConfig): string {
  return `# Nguard Authentication Configuration
# Generated by Nguard Setup CLI

# JWT Secret (minimum 32 characters)
# Generate with: openssl rand -base64 32
NGUARD_SECRET=your-secret-min-32-chars-here

# Backend API URL
# This is where your authentication backend is running
BACKEND_API_URL=http://localhost:8080/api

# Environment
NODE_ENV=${config.environment}

# Session cookie configuration (optional)
# NGUARD_COOKIE_NAME=${config.cookieName}
# NGUARD_COOKIE_SECURE=true (for HTTPS)
# NGUARD_COOKIE_SAME_SITE=Strict
`;
}

function printNextSteps(config: SetupConfig) {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📝 NEXT STEPS\n');

  console.log('1. 🔐 Set up environment variables:');
  console.log('   cp .env.local.example .env.local');
  console.log('   # Edit .env.local with your configuration\n');

  console.log('2. 📦 Install dependencies:');
  console.log('   npm install nguard\n');

  console.log('3. 🔧 Update your app/layout.tsx:');
  console.log("   Add SessionProvider from 'nguard/client'\n");

  console.log('4. 📚 Read the documentation:');
  console.log('   - Docs: https://github.com/trxyazilimedu/nguard');
  console.log('   - QUICKSTART: docs/en/QUICKSTART.md');
  console.log('   - API Reference: docs/en/API-CLIENT.md\n');

  console.log('5. ✅ Test your setup:');
  console.log('   npm run dev');
  console.log('   Visit http://localhost:3000\n');

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}

// Run the setup
main().catch(console.error);
