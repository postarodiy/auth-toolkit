import type { CheckResult, PermissionEngine, RbacAuthContext } from './permission-engine';

export interface RouteRuleDef<TRole extends string = string, TPermission extends string = string> {
  /** Any of these permissions grants access. */
  permissions?: TPermission[];
  /** Any of these roles grants access. */
  roles?: TRole[];
  /** If true, only the role check applies - no permission fallback. */
  roleOnly?: boolean;
  check?: (auth: RbacAuthContext<TRole, TPermission>) => boolean | Promise<boolean>;
}

export class RouteMatcher<TRole extends string = string, TPermission extends string = string> {
  constructor(
    private readonly rules: Record<string, RouteRuleDef<TRole, TPermission>>,
    private readonly engine: PermissionEngine<TRole, TPermission>
  ) {}

  /** Exact match first, then a trailing `/*` wildcard match. */
  findRule(pathname: string): RouteRuleDef<TRole, TPermission> | null {
    if (this.rules[pathname]) return this.rules[pathname];

    for (const [pattern, rule] of Object.entries(this.rules)) {
      if (pattern.endsWith('/*')) {
        const base = pattern.slice(0, -2);
        if (pathname === base || pathname.startsWith(base + '/')) return rule;
      }
    }

    return null;
  }

  async checkAccess(auth: RbacAuthContext<TRole, TPermission> | null, pathname: string): Promise<CheckResult> {
    const rule = this.findRule(pathname);
    if (!rule) return { allowed: true };

    if (!auth) return { allowed: false, reason: 'Not authenticated' };

    if (rule.check) {
      const passed = await rule.check(auth);
      if (!passed) return { allowed: false, reason: 'Custom check failed' };
    }

    if (rule.roles && rule.roles.length > 0) {
      if (this.engine.hasAnyRole(auth, rule.roles)) return { allowed: true };
      if (rule.roleOnly) {
        return { allowed: false, reason: `Required role: ${rule.roles.join(' or ')}` };
      }
    }

    if (rule.permissions && rule.permissions.length > 0) {
      const allowed = await this.engine.canAny(auth, rule.permissions);
      if (!allowed) {
        return { allowed: false, reason: `Required permission: ${rule.permissions.join(' or ')}` };
      }
    }

    return { allowed: true };
  }
}
