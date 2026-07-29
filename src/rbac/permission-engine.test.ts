import { describe, test, expect, vi } from 'vitest';
import { PermissionEngine, type RbacAuthContext, type PermissionEngineOptions } from './permission-engine';

type Role = 'admin' | 'editor' | 'viewer';
type Permission = 'posts.view' | 'posts.edit' | 'posts.delete';

function makeEngine(overrides?: Partial<PermissionEngineOptions<Role, Permission>>) {
  const getPermissions = vi.fn(async (role: Role): Promise<Permission[]> => {
    if (role === 'editor') return ['posts.view', 'posts.edit'];
    if (role === 'viewer') return ['posts.view'];
    return [];
  });

  const engine = new PermissionEngine<Role, Permission>({
    adminRole: 'admin',
    getPermissions,
    ...overrides,
  });

  return { engine, getPermissions };
}

describe('PermissionEngine.can', () => {
  test('admin role bypasses permission lookup entirely', async () => {
    const { engine, getPermissions } = makeEngine();
    const auth: RbacAuthContext<Role, Permission> = { role: 'admin' };

    expect(await engine.can(auth, 'posts.delete')).toBe(true);
    expect(getPermissions).not.toHaveBeenCalled();
  });

  test('grants a permission the role has', async () => {
    const { engine } = makeEngine();
    expect(await engine.can({ role: 'editor' }, 'posts.edit')).toBe(true);
  });

  test('denies a permission the role lacks', async () => {
    const { engine } = makeEngine();
    expect(await engine.can({ role: 'viewer' }, 'posts.delete')).toBe(false);
  });

  test('denies when auth is null', async () => {
    const { engine } = makeEngine();
    expect(await engine.can(null, 'posts.view')).toBe(false);
  });

  test('uses auth.permissions directly when provided, skipping the fetcher', async () => {
    const { engine, getPermissions } = makeEngine();
    const allowed = await engine.can({ role: 'viewer', permissions: ['posts.delete'] }, 'posts.delete');
    expect(allowed).toBe(true);
    expect(getPermissions).not.toHaveBeenCalled();
  });

  test('applies implicit permissions granted outside the fetched list', async () => {
    const { engine } = makeEngine({
      implicitPermissions: { viewer: ['posts.edit'] },
    });
    expect(await engine.can({ role: 'viewer' }, 'posts.edit')).toBe(true);
  });

  test('does not apply another role\'s implicit permissions', async () => {
    const { engine } = makeEngine({
      implicitPermissions: { editor: ['posts.delete'] },
    });
    expect(await engine.can({ role: 'viewer' }, 'posts.delete')).toBe(false);
  });
});

describe('PermissionEngine.canAny / canAll', () => {
  test('canAny is true if at least one permission matches', async () => {
    const { engine } = makeEngine();
    expect(await engine.canAny({ role: 'viewer' }, ['posts.delete', 'posts.view'])).toBe(true);
  });

  test('canAny is false if none match', async () => {
    const { engine } = makeEngine();
    expect(await engine.canAny({ role: 'viewer' }, ['posts.delete', 'posts.edit'])).toBe(false);
  });

  test('canAll requires every permission to match', async () => {
    const { engine } = makeEngine();
    expect(await engine.canAll({ role: 'editor' }, ['posts.view', 'posts.edit'])).toBe(true);
    expect(await engine.canAll({ role: 'editor' }, ['posts.view', 'posts.delete'])).toBe(false);
  });

  test('admin passes canAny/canAll unconditionally', async () => {
    const { engine } = makeEngine();
    expect(await engine.canAny({ role: 'admin' }, ['posts.delete'])).toBe(true);
    expect(await engine.canAll({ role: 'admin' }, ['posts.delete', 'posts.edit'])).toBe(true);
  });
});

describe('PermissionEngine.check / checkAny', () => {
  test('check returns allowed:false with a reason for an unauthenticated request', async () => {
    const { engine } = makeEngine();
    const result = await engine.check(null, 'posts.view');
    expect(result).toEqual({ allowed: false, reason: 'Not authenticated' });
  });

  test('check returns allowed:true with no reason on success', async () => {
    const { engine } = makeEngine();
    expect(await engine.check({ role: 'editor' }, 'posts.view')).toEqual({ allowed: true });
  });

  test('check includes the missing permission in the reason', async () => {
    const { engine } = makeEngine();
    const result = await engine.check({ role: 'viewer' }, 'posts.delete');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('posts.delete');
  });

  test('checkAny includes all candidate permissions in the reason', async () => {
    const { engine } = makeEngine();
    const result = await engine.checkAny({ role: 'viewer' }, ['posts.edit', 'posts.delete']);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('posts.edit');
    expect(result.reason).toContain('posts.delete');
  });
});

describe('PermissionEngine.hasRole / hasAnyRole', () => {
  test('hasRole matches exactly', () => {
    const { engine } = makeEngine();
    expect(engine.hasRole({ role: 'admin' }, 'admin')).toBe(true);
    expect(engine.hasRole({ role: 'editor' }, 'admin')).toBe(false);
    expect(engine.hasRole(null, 'admin')).toBe(false);
  });

  test('hasAnyRole matches any candidate', () => {
    const { engine } = makeEngine();
    expect(engine.hasAnyRole({ role: 'editor' }, ['admin', 'editor'])).toBe(true);
    expect(engine.hasAnyRole({ role: 'viewer' }, ['admin', 'editor'])).toBe(false);
    expect(engine.hasAnyRole(null, ['admin'])).toBe(false);
  });
});
