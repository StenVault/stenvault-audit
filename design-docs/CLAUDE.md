# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Before Starting Work

> **📍 IMPLEMENTATION ROADMAP**: `NEW_DAY.md` — Current implementation plan (Web First strategy)
> **📋 STRATEGIC ROADMAP**: `SOVEREIGN_ROADMAP.md` — Cryptographic architecture phases
>
> These are the ONLY tracking documents. Do NOT create additional tracking files.

### Session Rules

1. **Check `NEW_DAY.md` FIRST** — Current implementation plan
2. **Check git history BEFORE claiming issues** — `git log --oneline -20`
3. **DO NOT re-audit completed code** — Etapas/Phases marked ✅ are done
4. **DO NOT create tracking files** — No `fix_now.md`, `TODO.md`, etc.
5. **Ask before "fixing" intentional designs** — Many patterns are deliberate
6. **Don't change crypto parameters** (HMAC lengths, salts, Argon2id params) without explicit request

---

## Commands

```bash
# Development
pnpm dev                # Start API (port 3000) + Web (port 5173) in parallel
pnpm dev:api            # Vault API only
pnpm dev:web            # Web frontend only
pnpm start              # Production: run built API (serves web static files)

# Testing
pnpm test               # Run all tests (Vitest, 3400+)
pnpm test apps/api/src/_core/tests/filesRouter.test.ts  # Single test file
pnpm test:watch         # Watch mode
pnpm test:coverage      # Run with V8 coverage
pnpm test:ui            # Vitest browser UI
pnpm test:e2e           # Playwright E2E tests
pnpm test:e2e:headed    # E2E with visible browser
pnpm test:e2e:debug     # E2E with Playwright inspector

# Build & Check
pnpm build              # Typecheck + build all packages
pnpm typecheck          # Type-check all packages in parallel
pnpm format             # Prettier
pnpm clean              # Remove all dist/ and node_modules/

# Database (Drizzle ORM)
pnpm db:push            # Push schema changes (dev only — use db:migrate in prod)
pnpm db:generate        # Generate migrations
pnpm db:studio          # Open Drizzle Studio
pnpm db:seed:admin      # Create admin user

# Workspace filtering
pnpm --filter @cloudvault/api build
pnpm --filter @cloudvault/web dev
```

---

## Architecture

### Monorepo Structure

pnpm workspaces + Turborepo (`turbo.json`). Three packages:

| Package | Path | Purpose |
|---------|------|---------|
| `@cloudvault/api` | `apps/api/` | Express + tRPC v11 backend |
| `@cloudvault/web` | `apps/web/` | React 19 + Vite 7 frontend |
| `@cloudvault/shared` | `packages/shared/` | Shared types, utilities, platform abstraction |

### Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Node.js 20, Express, tRPC v11, Drizzle ORM, PostgreSQL |
| **Frontend** | React 19, TypeScript strict, Vite 7, TailwindCSS 4, Wouter |
| **Storage** | Cloudflare R2 (S3-compatible), Redis (Upstash) |
| **Encryption** | AES-256-GCM, Argon2id, X25519 + ML-KEM-768, Ed25519 + ML-DSA-65 |
| **Auth** | OPAQUE (RFC 9807) zero-knowledge, JWT, MFA/TOTP |
| **Testing** | Vitest, Playwright |

### tRPC Router Hierarchy

```
appRouter (apps/api/src/routers.ts)
├── auth              # JWT, OPAQUE, MFA, magic links, password reset, sessions
├── settings          # User settings, AI config
├── files             # Upload, download, trash, metadata (MODULAR: apps/api/src/_core/files/)
├── folders           # CRUD, breadcrumbs
├── shares            # Password-protected file sharing
├── chat              # E2E encrypted messaging (MODULAR: apps/api/src/_core/chat/)
├── chatFileShare     # File sharing within chat
├── p2p               # Quantum Mesh WebRTC signaling (apps/api/src/_core/p2p/)
├── admin             # System administration (MODULAR: apps/api/src/_core/admin/)
├── stripe            # Subscription management
├── mfa               # Two-factor authentication (TOTP)
├── encryption        # Master key management, verification hash, key wrapping
├── devices           # Trusted device management
├── deviceApproval    # Device approval workflow (UES)
├── hybridKem         # ML-KEM-768 + X25519 key pairs
├── hybridSignature   # ML-DSA-65 + Ed25519 signatures
├── organizations     # Org management
├── orgKeyManagement  # Org-level key management
├── users             # User profiles
├── timestamp         # Proof-of-existence timestamps
├── shamirRecovery    # Shamir secret sharing (K-of-N)
├── hsm               # HSM integration (Phase 3.2 roadmap — no frontend yet)
└── publicSend        # Anonymous encrypted file sharing (apps/api/src/_core/publicSend/)
```

**Modular router pattern**: Large routers are split into procedure files in a directory, combined via `index.ts`:
```typescript
// apps/api/src/_core/files/index.ts
export const filesRouter = router({
  ...uploadProcedures,
  ...downloadProcedures,
  ...manageProcedures,
});
```

### Frontend Architecture

**Route Guards** (composition-based, Wouter):
- `AuthGuard` — redirects unauthenticated to `/landing`
- `GuestGuard` — redirects authenticated to `/dashboard`
- `AdminGuard` — requires auth + admin role
- Location: `apps/web/src/routes/guards/`

**State Management**:
- TanStack Query (via tRPC) for server state
- Zustand for client state (UI, preferences)

**Mobile UI**: Separate component system in `apps/web/src/components/mobile-v2/` (not CSS media queries). Detection via `useIsMobile()` hook.

**Landing Page Design System** (`apps/web/src/components/landing/`):
- Colors: `LANDING_COLORS` in `constants/colors.ts` (bg: #020617, accent: #6366F1 indigo)
- Components: `GradientMesh`, `SpotlightCard`, `MagneticButton`, `FeatureCard`, `LazySection`
- Animations: GSAP + ScrollTrigger, Framer Motion, Lenis smooth scroll
- Hooks: `use3DScrollAnimations`, `useSmoothScroll`, `useReducedMotion`

### Shared Package (`@cloudvault/shared`)

Canonical sources — avoid local duplicates:
- `FileType` / `FileTypeNoFolder` — `types/files`
- `formatBytes()`, `formatDate()` — root exports
- `arrayBufferToBase64` — root export
- `deriveChunkIV` — `platform/crypto/utils`

---

## Encryption Architecture

### Zero-Knowledge Model

Server never sees: file content, filenames, or master password.

### Key Derivation Flow

```
Password → Argon2id (47 MiB, t=1, p=1) → KEK → AES-KW Unwrap → Master Key (32B)
                                                                    ├─ File Encryption (AES-256-GCM)
                                                                    └─ Filename Encryption (derived key)
```

With **User Entropy Seed (UES)**: dual-KEK system — device-specific fast path (~100ms) + password-only slow path (~500ms). New devices require approval or recovery code.

### Encryption Versions

- **V3**: Master Key + HKDF
- **V4** (primary): Hybrid PQC — X25519-ECDH + ML-KEM-768 → HKDF-SHA256 → AES-KW wrapped file key. CVEF v1.2 format.

Key implementation files: `apps/web/src/lib/fileCrypto.ts`, `streamingCrypto.ts`, `hybridFileCrypto.ts`

### Public Send (`/send`)

Anonymous encrypted file sharing — no account required:
- Client generates random AES-256-GCM key, encrypts file in 5MB chunks
- Key placed in URL fragment (`#key=base64url`) — never sent to server per HTTP spec
- Sessions stored in Redis with TTL (1h/24h/7d), encrypted blob in R2
- Backend: `apps/api/src/_core/publicSend/` (types, storage, featureToggle, 4 procedures)
- Frontend: `apps/web/src/lib/publicSendCrypto.ts`, `hooks/usePublicSend.ts`, `pages/SendPage.tsx`, `pages/ReceivePage.tsx`
- Feature toggle: `FEATURE_PUBLIC_SEND=true` env var + admin setting

### OPAQUE Authentication (RFC 9807)

Email+password auth via `@serenity-kit/opaque` — server never sees the password.
- Backend: `apps/api/src/_core/opaqueAuth.ts`
- Frontend: `apps/web/src/lib/opaqueClient.ts`
- Requires `OPAQUE_SERVER_SETUP` env var (generate: `npx @serenity-kit/opaque create-server-setup`)

---

## Important Patterns

### Adding a tRPC Procedure

1. Create `apps/api/src/_core/{feature}/newProcedure.ts`
2. Define Zod input schemas
3. Use `protectedProcedure` (auth required) or `publicProcedure`
4. Export procedures object, spread into router `index.ts`

### Adding a Frontend Route

1. Create page in `apps/web/src/pages/`
2. Add to `apps/web/src/App.tsx` with appropriate guard (`AuthGuard`, `GuestGuard`, or public)
3. Lazy import for code splitting: `const MyPage = lazy(() => import("@/pages/MyPage"))`

### Platform Abstraction

Originally designed for React Native, now used for web-only. Mobile app is separate Kotlin Multiplatform repo at `D:\Projects\Cloud\cloudvault-mobile`.

Interfaces in `packages/shared/src/platform/`, web implementations in `apps/web/src/lib/platform/`.

### Crypto Gotchas

- **ML-KEM-768 secret key = 2400 bytes**: Can't use AES-KW (32B max). Use `encryptLargeSecretKey`/`decryptLargeSecretKey` helpers.
- **Presigned URL ContentLength**: Never include ContentLength for upload URLs — client encrypts after getting URL, actual size unknown. R2 rejects mismatch with 403.
- **`?? []` in effect deps**: Creates new array ref each render when data is undefined → infinite re-render loop. Fix: `useMemo(() => data?.files ?? [], [data?.files])`.
- **`encryptionVersion ?? 3` fallback**: Non-encrypted files get routed to decrypt. Fix: `?? (isEncrypted ? 3 : 1)`.

---

## Environment Variables

### Required

```env
DATABASE_URL="postgresql://..."
R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME
JWT_SECRET                    # Min 32 chars
ENCRYPTION_KEY                # Min 32 chars, different from JWT_SECRET
OPAQUE_SERVER_SETUP           # Generate: npx @serenity-kit/opaque create-server-setup
OPS_DECK_SECRET               # Generate: openssl rand -hex 32 — no fallback, required
INTERNAL_SECRET               # Service-to-service auth — no fallback, required
```

### Optional

```env
RESEND_API_KEY                # Email features (disabled if missing)
REDIS_URL, REDIS_TOKEN        # Rate limiting + Public Send sessions
FEATURE_PUBLIC_SEND=true      # Enable /send anonymous file sharing
FEATURE_P2P_SHARING=true      # Enable P2P transfers
```

---

## Deployment

**Railway (production)**: Single service — `pnpm build` then `node apps/api/dist/main.js`. API serves web static files from `apps/web/dist`.

---

## Current Status (2026-02)

**Web**: 100% zero-knowledge complete (Etapas 1-7.2, 9.1). Server never sees files, filenames, or passwords.
**Mobile**: Kotlin Multiplatform at `D:\Projects\Cloud\cloudvault-mobile` — porting next.
**SOVEREIGN Phases**: 0-2, 3.1 (Shamir), 3.2 (HSM), 3.4 (Signatures) complete.
