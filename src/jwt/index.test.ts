import { describe, test, expect, vi, afterEach } from 'vitest';
import { signJwt, verifyJwt, buildSessionCookie, buildClearCookie } from './index';

const secret = 'test-secret-value';

afterEach(() => {
  vi.useRealTimers();
});

// A declared interface, not an inline object literal type. TypeScript only
// auto-satisfies a `Record<string, unknown>` generic constraint for fresh
// literal types, not named interfaces - most real callers pass one of these,
// so signJwt/verifyJwt must accept it too (regression test for a real
// integration failure hit when wiring this package into a consuming app).
interface AppJwtPayload {
  userId: number;
  role: string;
  mustChangePassword?: boolean;
}

describe('signJwt / verifyJwt', () => {
  test('accepts a named interface payload, not just inline object literals', async () => {
    const token = await signJwt<AppJwtPayload>({ userId: 1, role: 'admin' }, { secret });
    const payload = await verifyJwt<AppJwtPayload>(token, { secret });

    expect(payload).not.toBeNull();
    expect(payload?.userId).toBe(1);
    expect(payload?.role).toBe('admin');
  });

  test('round trips a generic payload', async () => {
    const token = await signJwt({ userId: 1, role: 'admin' }, { secret });
    const payload = await verifyJwt<{ userId: number; role: string }>(token, { secret });

    expect(payload).not.toBeNull();
    expect(payload?.userId).toBe(1);
    expect(payload?.role).toBe('admin');
    expect(payload?.iat).toEqual(expect.any(Number));
    expect(payload?.exp).toEqual(expect.any(Number));
  });

  test('produces a well-formed three-part JWT', async () => {
    const token = await signJwt({ sub: 'x' }, { secret });
    expect(token.split('.')).toHaveLength(3);
  });

  test('two tokens signed in the same instant are unique when jwtId is requested', async () => {
    const [a, b] = await Promise.all([
      signJwt({ sub: 'x' }, { secret, jwtId: true }),
      signJwt({ sub: 'x' }, { secret, jwtId: true }),
    ]);
    expect(a).not.toBe(b);
  });

  test('jwtId accepts a custom id source', async () => {
    const token = await signJwt({ sub: 'x' }, { secret, jwtId: () => 'fixed-id' });
    const [, payloadB64] = token.split('.');
    const decoded = JSON.parse(Buffer.from(payloadB64!, 'base64url').toString());
    expect(decoded.jti).toBe('fixed-id');
  });

  test('returns null for an empty token', async () => {
    expect(await verifyJwt('', { secret })).toBeNull();
  });

  test('returns null for a malformed token', async () => {
    expect(await verifyJwt('not-a-jwt', { secret })).toBeNull();
  });

  test('returns null when the secret does not match', async () => {
    const token = await signJwt({ sub: 'x' }, { secret });
    expect(await verifyJwt(token, { secret: 'wrong-secret' })).toBeNull();
  });

  test('returns null for a tampered signature', async () => {
    const token = await signJwt({ sub: 'x' }, { secret });
    const [header, payload, signature] = token.split('.');
    const tampered = `${header}.${payload}.${signature}abc`;
    expect(await verifyJwt(tampered, { secret })).toBeNull();
  });

  test('returns null for a tampered payload', async () => {
    const token = await signJwt({ role: 'user' }, { secret });
    const [header, payload, signature] = token.split('.');
    const decoded = JSON.parse(Buffer.from(payload!, 'base64url').toString());
    decoded.role = 'admin';
    const tamperedPayload = Buffer.from(JSON.stringify(decoded)).toString('base64url');
    expect(await verifyJwt(`${header}.${tamperedPayload}.${signature}`, { secret })).toBeNull();
  });

  test('returns null for an expired token', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    const token = await signJwt({ sub: 'x' }, { secret, expiresIn: '1h' });

    vi.setSystemTime(new Date('2024-01-01T02:00:00Z'));
    expect(await verifyJwt(token, { secret })).toBeNull();
  });

  test('honors a custom algorithm end to end', async () => {
    const token = await signJwt({ sub: 'x' }, { secret, algorithm: 'HS512' });
    const payload = await verifyJwt(token, { secret, algorithms: ['HS512'] });
    expect(payload).not.toBeNull();
  });

  test('rejects a token signed with an algorithm outside the verify allowlist', async () => {
    const token = await signJwt({ sub: 'x' }, { secret, algorithm: 'HS512' });
    // Default verifyJwt allowlist is ['HS256'] - a HS512 token must be rejected.
    expect(await verifyJwt(token, { secret })).toBeNull();
  });

  test('rejects a forged "none" algorithm token', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'attacker', role: 'admin' })).toString('base64url');
    const forged = `${header}.${payload}.`;
    expect(await verifyJwt(forged, { secret })).toBeNull();
  });
});

describe('buildSessionCookie / buildClearCookie', () => {
  test('builds a session cookie with the given config', () => {
    const cookie = buildSessionCookie('token-value', {
      cookieName: 'access_token',
      secure: true,
      maxAgeSeconds: 86400,
    });

    expect(cookie).toEqual({
      name: 'access_token',
      value: 'token-value',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 86400,
      path: '/',
    });
  });

  test('builds a clear cookie with maxAge 0 and an empty value', () => {
    const cookie = buildClearCookie({ cookieName: 'access_token', secure: false });

    expect(cookie.value).toBe('');
    expect(cookie.maxAge).toBe(0);
    expect(cookie.secure).toBe(false);
  });

  test('respects custom sameSite and path', () => {
    const cookie = buildSessionCookie('t', {
      cookieName: 'session',
      secure: true,
      maxAgeSeconds: 3600,
      sameSite: 'strict',
      path: '/app',
    });

    expect(cookie.sameSite).toBe('strict');
    expect(cookie.path).toBe('/app');
  });
});
