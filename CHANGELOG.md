# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-01-15

### Added

#### Default Login/Logout Functions
- SessionProvider now includes built-in default login handler for `POST /api/auth/login`
- SessionProvider now includes built-in default logout handler for `POST /api/auth/logout`
- **Breaking Change**: No need to provide `onLogin` and `onLogout` callbacks anymore
- All SessionProvider props are now optional
- Callbacks can still be overridden if custom behavior is needed

#### Server-Side Session Access
- New `auth()` function in `lib/auth.ts` for Next.js server components
- Works like NextAuth's `auth()` function
- Can be used in Server Components and API routes
- Helper functions: `createSession()`, `clearSession()`, `validateSession()`
- Middleware helpers: `authMiddleware()`, `withRole()`

#### Flexible Backend Integration
- Removed hardcoded database examples from documentation
- Support for any backend (Spring, Express, Node.js, Python, etc.)
- Frontend acts as a proxy/middleware between client and backend
- Complete backend-agnostic architecture

#### Documentation & Examples
- New comprehensive `SESSION-UPDATE.md` guide for session updates
- English and Turkish versions of all documentation
- Complete example files:
  - `lib-auth-function.ts` - Server-side auth() implementation
  - `auth-usage-examples.tsx` - Server/Client usage examples
  - `app-layout-default.tsx` - Full working layout with pages
  - `api-auth-routes.ts` - All API route examples
  - `components-update-session.tsx` - Session update components
  - `backend-update-role-spring.java` - Spring backend examples
  - `backend-update-preferences-spring.java` - Preferences endpoints
  - `backend-dtos-spring.java` - Backend DTOs
- `.env.example` file for configuration

### Changed

- QUICKSTART.md now shows zero-config SessionProvider setup
- Client setup in app/layout.tsx simplified (no callbacks needed)
- Updated all documentation to reflect backend-agnostic architecture
- SessionProvider props are now fully optional (children is optional)
- Better type safety and JSDoc comments

### Improved

- Better error handling in default login/logout
- More comprehensive examples for both server and client
- Clearer separation of concerns (frontend vs backend)
- Documentation now includes both Turkish (TR) and English (EN)

### Fixed

- SessionProvider now gracefully handles missing callbacks
- Better fallback behavior for session initialization

## [0.1.1] - 2024-01-10

### Added

- Initial package.json with basic metadata
- Support for Next.js 16+
- React 18+ compatibility

## [0.1.0] - 2024-01-05

### Initial Release

- Basic session management library
- JWT-based authentication
- Server-side and client-side callbacks
- React hooks for authentication
- TypeScript support
