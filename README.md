# @postarodiy/auth-toolkit

Framework-agnostic auth primitives: JWT signing/verification, password
hashing, rate limiting, and an RBAC permission-checking engine. Extracted
from [presa-management](https://github.com/postarodiy) so future projects
don't re-implement (and re-audit) the same auth mechanics from scratch.

## Contents

- [What this is not](#what-this-is-not)
- [Install](#install)
  - [1. Point npm at the registry](#1-point-npm-at-the-registry)
  - [2. Local development](#2-local-development)
  - [3. CI (GitHub Actions)](#3-ci-github-actions)
- [`/jwt`](#jwt)
- [`/password`](#password)
- [`/ratelimit`](#ratelimit)
- [`/rbac`](#rbac)
- [Security](#security)
- [Development](#development)
- [Publishing](#publishing)

<a id="what-this-is-not"></a>
## What this is not

This package has no framework glue (no Next.js middleware, no Express
routes), no database layer, and no opinion on your role/permission names.
Every module takes plain data in and returns plain data out. Wire it up to
your framework and database in your own app.

There is deliberately **no root `.` export** - only subpath imports below.
This keeps each module's dependencies isolated, so importing `./jwt` in an
edge/serverless bundle can never accidentally pull in `bcryptjs` or the
rate limiter's timers.

<a id="install"></a>
## Install

GitHub Packages requires authentication to install, even for a public repo
like this one - the package itself is private. There are two separate setups
below: local development and CI. They use different auth mechanisms.

<a id="1-point-npm-at-the-registry"></a>
### 1. Point npm at the registry

In the consuming project's `.npmrc` (commit this file, it has no secret in it):

```
# .npmrc
@postarodiy:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

The token itself comes from an environment variable, never hardcode it here.

<a id="2-local-development"></a>
### 2. Local development

You need a token with `read:packages` scope. Either works:

```
# Add the scope to your existing gh CLI login (opens a device-code browser flow)
gh auth refresh -h github.com -s read:packages

# Then export it for npm to pick up (add to your shell profile if you install often)
export GITHUB_PACKAGES_TOKEN="$(gh auth token)"
npm install @postarodiy/auth-toolkit
```

Or create a classic PAT with `read:packages` scope at
https://github.com/settings/tokens and export that instead.

<a id="3-ci-github-actions"></a>
### 3. CI (GitHub Actions)

The default `GITHUB_TOKEN` is scoped to the repo the workflow runs in - it
cannot read a package published from a *different* repo, even in the same
org, without an explicit grant. Rather than storing a PAT as a secret,
grant the consuming repo read access to this package directly:

1. Open this package's settings: https://github.com/orgs/postarodiy/packages/npm/package/auth-toolkit/settings
2. Under **Manage Actions access**, click **Add repository**, pick the
   consuming repo, set role to **Read**

Then the workflow needs no secret at all, just:

```yaml
permissions:
  packages: read

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: "22"
  - run: npm ci
    env:
      GITHUB_PACKAGES_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

<a id="jwt"></a>
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

<a id="password"></a>
## `@postarodiy/auth-toolkit/password`

```ts
import { hashPassword, verifyPassword } from '@postarodiy/auth-toolkit/password';

const hash = await hashPassword('plain-text-password'); // bcrypt, cost 10 by default
const ok = await verifyPassword('plain-text-password', hash);
```

<a id="ratelimit"></a>
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

<a id="rbac"></a>
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

<a id="security"></a>
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

<a id="development"></a>
## Development

```
npm install
npm run typecheck
npm test        # vitest, with coverage
npm run build   # tsup: ESM + CJS + .d.ts per subpath
```

<a id="publishing"></a>
## Publishing

Bump `version` in `package.json`, merge to `main`, then create a GitHub
Release tagged `vX.Y.Z` matching that version. The `publish.yml` workflow
verifies the tag matches, re-runs the full test suite, and publishes to
GitHub Packages.
