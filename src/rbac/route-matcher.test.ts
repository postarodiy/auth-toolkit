import { describe, test, expect } from 'vitest';
import { PermissionEngine } from './permission-engine';
import { RouteMatcher, type RouteRuleDef } from './route-matcher';

type Role = 'admin' | 'editor' | 'viewer';
type Permission = 'posts.view' | 'posts.edit';

function makeMatcher(rules: Record<string, RouteRuleDef<Role, Permission>>) {
  const engine = new PermissionEngine<Role, Permission>({
    adminRole: 'admin',
    getPermissions: async (role) => (role === 'editor' ? ['posts.view', 'posts.edit'] : ['posts.view']),
  });
  return new RouteMatcher<Role, Permission>(rules, engine);
}

describe('RouteMatcher.findRule', () => {
  test('matches an exact path', () => {
    const rule: RouteRuleDef<Role, Permission> = { permissions: ['posts.view'] };
    const matcher = makeMatcher({ '/posts': rule });
    expect(matcher.findRule('/posts')).toBe(rule);
  });

  test('matches a wildcard suffix', () => {
    const rule: RouteRuleDef<Role, Permission> = { permissions: ['posts.view'] };
    const matcher = makeMatcher({ '/posts/*': rule });
    expect(matcher.findRule('/posts/123')).toBe(rule);
    expect(matcher.findRule('/posts')).toBe(rule);
  });

  test('returns null for an unmatched path', () => {
    const matcher = makeMatcher({ '/posts': { permissions: ['posts.view'] } });
    expect(matcher.findRule('/comments')).toBeNull();
  });

  test('prefers an exact match over a wildcard', () => {
    const exact: RouteRuleDef<Role, Permission> = { roles: ['admin'] };
    const wildcard: RouteRuleDef<Role, Permission> = { permissions: ['posts.view'] };
    const matcher = makeMatcher({ '/posts/new': exact, '/posts/*': wildcard });
    expect(matcher.findRule('/posts/new')).toBe(exact);
  });
});

describe('RouteMatcher.checkAccess', () => {
  test('allows an unprotected path with no auth', async () => {
    const matcher = makeMatcher({});
    expect(await matcher.checkAccess(null, '/public')).toEqual({ allowed: true });
  });

  test('denies a protected path with no auth', async () => {
    const matcher = makeMatcher({ '/posts': { permissions: ['posts.view'] } });
    const result = await matcher.checkAccess(null, '/posts');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('Not authenticated');
  });

  test('grants access when the permission matches', async () => {
    const matcher = makeMatcher({ '/posts': { permissions: ['posts.view'] } });
    expect(await matcher.checkAccess({ role: 'viewer' }, '/posts')).toEqual({ allowed: true });
  });

  test('denies access when the permission is missing', async () => {
    const matcher = makeMatcher({ '/posts': { permissions: ['posts.edit'] } });
    const result = await matcher.checkAccess({ role: 'viewer' }, '/posts');
    expect(result.allowed).toBe(false);
  });

  test('roleOnly denies even if the permission would otherwise pass', async () => {
    const matcher = makeMatcher({
      '/admin': { roles: ['admin'], roleOnly: true, permissions: ['posts.view'] },
    });
    const result = await matcher.checkAccess({ role: 'viewer' }, '/admin');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('admin');
  });

  test('without roleOnly, falls through to the permission check', async () => {
    const matcher = makeMatcher({
      '/posts': { roles: ['admin'], permissions: ['posts.view'] },
    });
    expect(await matcher.checkAccess({ role: 'viewer' }, '/posts')).toEqual({ allowed: true });
  });

  test('a custom check function can veto access', async () => {
    const matcher = makeMatcher({
      '/posts': { check: () => false },
    });
    const result = await matcher.checkAccess({ role: 'admin' }, '/posts');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('Custom check failed');
  });

  test('a custom check function can be async', async () => {
    const matcher = makeMatcher({
      '/posts': { check: async () => true },
    });
    expect(await matcher.checkAccess({ role: 'viewer' }, '/posts')).toEqual({ allowed: true });
  });

  test('admin bypasses permission checks via the engine', async () => {
    const matcher = makeMatcher({ '/posts': { permissions: ['posts.edit'] } });
    expect(await matcher.checkAccess({ role: 'admin' }, '/posts')).toEqual({ allowed: true });
  });
});
