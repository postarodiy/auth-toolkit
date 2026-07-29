# @postarodiy/auth-toolkit

Framework-agnostic auth primitives: JWT signing/verification, password
hashing, rate limiting, and an RBAC permission-checking engine. Extracted
from [presa-management](https://github.com/postarodiy) so future projects
don't re-implement (and re-audit) the same auth mechanics from scratch.

## What this is not

This package has no framework glue (no Next.js middleware, no Express
routes), no database layer, and no opinion on your role/permission names.
Every module takes plain data in and returns plain data out. Wire it up to
your framework and database in your own app.

There is deliberately **no root `.` export** - only subpath imports below.
This keeps each module's dependencies isolated, so importing `./jwt` in an
edge/serverless bundle can never accidentally pull in `bcryptjs` or the
rate limiter's timers.

## Install

Requires a GitHub Packages auth token (`read:packages` scope) configured
for the `@postarodiy` registry scope, since GitHub Packages requires
authentication for install regardless of repo visibility.

```
# .npmrc
@postarodiy:registry=https://npm.pkg.github.com
```

```
npm install @postarodiy/auth-toolkit
```

## `@postarodiy/auth-toolkit/jwt`

Edge-safe (no Node-only APIs), built on [`jose`](https://github.com/panva/jose).

```ts
import { signJwt, verifyJwt, buildSessionCookie, buildClearCookie } from '@postarodiy/auth-toolkit/jwt';

const token = await signJwt(
  { userId: 1, role: 'admin' },
  { secret: process.env.JWT_SECRET!, expiresIn: '24h', jwtId: true }
);

const payload = await verifyJwt<{ userId: number; role: string }>(token, {
  secret: process.env.JWT_SECRET!,
});
// payload is null for any invalid, expired, tampered, or algorithm-mismatched token

const cookie = buildSessionCookie(token, {
  cookieName: 'access_token',
  secure: true,
  maxAgeSeconds: 60 * 60 * 24,
});
```

**Always pass `algorithms` explicitly to `verifyJwt` if you sign with
anything other than the default `HS256`.** That allowlist is what stops
algorithm-confusion attacks - a token signed with one algorithm must not
verify under a different one.

## `@postarodiy/auth-toolkit/password`

```ts
import { hashPassword, verifyPassword } from '@postarodiy/auth-toolkit/password';

const hash = await hashPassword('plain-text-password'); // bcrypt, cost 10 by default
const ok = await verifyPassword('plain-text-password', hash);
```

## `@postarodiy/auth-toolkit/ratelimit`

Sliding-window request limiting plus failed-attempt blocking (e.g. for
login endpoints). **In-memory only** - state is per process, not shared
across instances. Fine for a single-instance deployment; do not rely on it
for correctness behind a load balancer with multiple replicas.

```ts
import { RateLimiter } from '@postarodiy/auth-toolkit/ratelimit';

const loginLimiter = new RateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  maxFailedAttempts: 5,
  blockDurationMs: 30 * 60 * 1000,
  onEvent: (event) => logger.warn(event.type, event),
});

if (!loginLimiter.isAllowed(ip)) {
  // 429
}
// ...on failed login:
loginLimiter.recordFailedAttempt(ip);
// ...on successful login:
loginLimiter.resetFailedAttempts(ip);

// Call destroy() in tests or on graceful shutdown to stop its background timer.
loginLimiter.destroy();
```

## `@postarodiy/auth-toolkit/rbac`

A generic permission-checking engine. It never talks to a database - you
inject a `getPermissions` fetcher (and own any caching around it), and the
engine just does the boolean logic.

```ts
import { PermissionEngine, RouteMatcher } from '@postarodiy/auth-toolkit/rbac';

type Role = 'admin' | 'editor' | 'viewer';
type Permission = 'posts.view' | 'posts.edit';

const engine = new PermissionEngine<Role, Permission>({
  adminRole: 'admin', // bypasses every check
  getPermissions: (role) => db.role.findPermissions(role), // your own lookup + caching
  implicitPermissions: { viewer: ['posts.view'] }, // granted regardless of the fetcher
});

await engine.can({ role: 'editor' }, 'posts.edit'); // boolean
await engine.check({ role: 'editor' }, 'posts.edit'); // { allowed, reason? }

const routes = new RouteMatcher<Role, Permission>(
  {
    '/posts': { permissions: ['posts.view'] },
    '/posts/*': { permissions: ['posts.view', 'posts.edit'] },
    '/admin': { roles: ['admin'], roleOnly: true },
  },
  engine
);

await routes.checkAccess({ role: 'viewer' }, '/posts/123'); // { allowed: true }
```

Role names, permission names, and route rules stay in your app - they're
business config that changes with the product, not generic code.

## Security

- JWT verification always requires an explicit algorithm allowlist
  (defaults to `HS256`) and rejects `none`/mismatched algorithms.
- Password hashing goes through `bcryptjs`; hashes are always salted per
  call, never reused.
- CI runs `npm audit --audit-level=high` on every push/PR, CodeQL static
  analysis on every push/PR plus a weekly schedule, and Dependabot keeps
  dependencies current.
- The rate limiter is in-memory and single-instance. It is not a substitute
  for a distributed store (e.g. Redis) if you're running multiple replicas.

Found a security issue? Open a private security advisory on this repo
rather than a public issue.

## Development

```
npm install
npm run typecheck
npm test        # vitest, with coverage
npm run build   # tsup: ESM + CJS + .d.ts per subpath
```

## Publishing

Bump `version` in `package.json`, merge to `main`, then create a GitHub
Release tagged `vX.Y.Z` matching that version. The `publish.yml` workflow
verifies the tag matches, re-runs the full test suite, and publishes to
GitHub Packages.
