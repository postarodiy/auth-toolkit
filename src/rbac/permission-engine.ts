export interface RbacAuthContext<TRole extends string = string, TPermission extends string = string> {
  role: TRole;
  permissions?: TPermission[];
}

export interface CheckResult {
  allowed: boolean;
  reason?: string;
}

export interface PermissionEngineOptions<TRole extends string, TPermission extends string> {
  /** A user with this role passes every check without a permission lookup. */
  adminRole?: TRole;
  /** App-owned lookup (DB query, cache, static map, ...) for a role's permissions. */
  getPermissions: (role: TRole) => Promise<TPermission[]>;
  /** Permissions granted to a role regardless of what getPermissions returns. */
  implicitPermissions?: Partial<Record<TRole, TPermission[]>>;
}

export class PermissionEngine<TRole extends string = string, TPermission extends string = string> {
  constructor(private readonly options: PermissionEngineOptions<TRole, TPermission>) {}

  private async resolvePermissions(auth: RbacAuthContext<TRole, TPermission>): Promise<TPermission[]> {
    return auth.permissions ?? this.options.getPermissions(auth.role);
  }

  private hasImplicit(role: TRole, permission: TPermission): boolean {
    return this.options.implicitPermissions?.[role]?.includes(permission) ?? false;
  }

  async can(auth: RbacAuthContext<TRole, TPermission> | null, permission: TPermission): Promise<boolean> {
    if (!auth?.role) return false;
    if (this.options.adminRole && auth.role === this.options.adminRole) return true;

    const permissions = await this.resolvePermissions(auth);
    return permissions.includes(permission) || this.hasImplicit(auth.role, permission);
  }

  async canAny(auth: RbacAuthContext<TRole, TPermission> | null, permissions: TPermission[]): Promise<boolean> {
    if (!auth?.role) return false;
    if (this.options.adminRole && auth.role === this.options.adminRole) return true;

    const granted = await this.resolvePermissions(auth);
    return permissions.some((p) => granted.includes(p) || this.hasImplicit(auth.role, p));
  }

  async canAll(auth: RbacAuthContext<TRole, TPermission> | null, permissions: TPermission[]): Promise<boolean> {
    if (!auth?.role) return false;
    if (this.options.adminRole && auth.role === this.options.adminRole) return true;

    const granted = await this.resolvePermissions(auth);
    return permissions.every((p) => granted.includes(p) || this.hasImplicit(auth.role, p));
  }

  async check(auth: RbacAuthContext<TRole, TPermission> | null, permission: TPermission): Promise<CheckResult> {
    if (!auth) return { allowed: false, reason: 'Not authenticated' };
    const allowed = await this.can(auth, permission);
    return allowed ? { allowed: true } : { allowed: false, reason: `Missing permission: ${permission}` };
  }

  async checkAny(auth: RbacAuthContext<TRole, TPermission> | null, permissions: TPermission[]): Promise<CheckResult> {
    if (!auth) return { allowed: false, reason: 'Not authenticated' };
    const allowed = await this.canAny(auth, permissions);
    return allowed
      ? { allowed: true }
      : { allowed: false, reason: `Missing permissions: ${permissions.join(' or ')}` };
  }

  hasRole(auth: RbacAuthContext<TRole, TPermission> | null, role: TRole): boolean {
    return auth?.role === role;
  }

  hasAnyRole(auth: RbacAuthContext<TRole, TPermission> | null, roles: TRole[]): boolean {
    return auth?.role ? roles.includes(auth.role) : false;
  }
}
