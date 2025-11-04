# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2025-01-15

### Fixed

- Removed unnecessary console.error and console.warn from authentication functions
- Login, logout, and session update no longer log errors to console
- Cleaner console output for production environments
- Error responses contain full error details without console pollution

## [0.2.1] - 2025-01-15

### Fixed

- Fixed JWT encoding error: "expiresIn option the payload already has an exp property"
- JWTHandler.encode() now correctly handles payloads with pre-set exp property
- Removed conflicting expiresIn option when payload already contains exp field

### Added

#### Response Type Exports
- `LoginResponse` now exported from main API
- `LogoutResponse` now exported from main API
- `UpdateSessionResponse` now exported from main API
- Enables type-safe response handling in user applications

#### Documentation Enhancements
- New `API-CLIENT.md` comprehensive client API reference (English & Turkish)
- Updated QUICKSTART.md with response handling examples
- Added best practices section for response handling
- Added error handling patterns and examples
- Complete hook documentation with TypeScript examples

### Improved

- Better response handling documentation with examples
- Type-safe imports for response types
- Clearer error handling patterns in client code

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
