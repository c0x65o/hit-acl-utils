export type PrincipalType = 'user' | 'group' | 'role';

/**
 * Minimal request shape needed for principal expansion.
 * Compatible with Next.js `NextRequest` (and similar request abstractions).
 */
export interface RequestLike {
  headers: { get(name: string): string | null };
  nextUrl?: { protocol?: string; host?: string };
}

export interface UserClaimsLike {
  sub: string;
  email?: string;
  roles?: string[];
  groups?: string[];
}

export interface ResolvedUserPrincipals {
  userId: string;
  userEmail: string;
  roles: string[];
  groupIds: string[];
}

export interface ResolveUserPrincipalsOptions {
  request?: RequestLike;
  user: UserClaimsLike;
  /**
   * Include groups provided by the JWT (if present). Defaults to true.
   */
  includeTokenGroups?: boolean;
  /**
   * Include groups from the auth module `/me/groups` endpoint (includes dynamic groups). Defaults to true.
   */
  includeAuthMeGroups?: boolean;
  /**
   * Fail fast when group expansion cannot be performed.
   *
   * When true, this function throws instead of silently returning partial/incomplete groupIds.
   * This is recommended for permission enforcement paths where "missing groups" should be treated
   * as an error (fail closed) rather than "best effort" (fail open-ish).
   *
   * Defaults to false for backwards compatibility.
   */
  strict?: boolean;
  /**
   * Optional additional group id sources (feature-pack specific), e.g. vault's own group membership tables.
   */
  extraGroupIds?: () => Promise<string[]>;
}

let _warnedNoRequest = false;
let _warnedNoAuthForMeGroups = false;
let _warnedNoServiceTokenForAdminGroups = false;
function warnOnce(kind: 'no_request' | 'no_auth_for_me_groups' | 'no_service_token_admin_groups', msg: string) {
  if (kind === 'no_request') {
    if (_warnedNoRequest) return;
    _warnedNoRequest = true;
  } else if (kind === 'no_auth_for_me_groups') {
    if (_warnedNoAuthForMeGroups) return;
    _warnedNoAuthForMeGroups = true;
  } else if (kind === 'no_service_token_admin_groups') {
    if (_warnedNoServiceTokenForAdminGroups) return;
    _warnedNoServiceTokenForAdminGroups = true;
  }
  console.warn(msg);
}

function uniqStrings(xs: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of xs) {
    const s = String(raw || '').trim();
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

function baseUrlFromRequest(request: RequestLike): string {
  const proto =
    request.headers.get('x-forwarded-proto') ||
    request.nextUrl?.protocol?.replace(':', '') ||
    'http';
  const host =
    request.headers.get('x-forwarded-host') ||
    request.headers.get('host') ||
    request.nextUrl?.host ||
    '';
  return `${proto}://${host}`;
}

function getBearerFromRequest(request: RequestLike): string | null {
  const authz = request.headers.get('authorization');
  if (authz?.startsWith('Bearer ')) return authz;

  const cookie = request.headers.get('cookie') || '';
  if (!cookie) return null;

  const parts = cookie.split(';').map((c) => c.trim());
  for (const p of parts) {
    const eqIdx = p.indexOf('=');
    if (eqIdx <= 0) continue;
    const name = p.slice(0, eqIdx);
    const value = p.slice(eqIdx + 1);
    if (name === 'hit_token' && value) {
      return `Bearer ${value}`;
    }
  }
  return null;
}

function getAuthBaseUrl(request?: RequestLike): string | null {
  // Prefer direct module URL (server-side)
  const direct = process.env.HIT_AUTH_URL || process.env.NEXT_PUBLIC_HIT_AUTH_URL;
  if (direct) return direct.replace(/\/$/, '');

  // Fallback to app-local proxy route
  if (request) {
    return `${baseUrlFromRequest(request)}/api/proxy/auth`;
  }

  return null;
}

async function fetchAuthMeGroupIds(request: RequestLike, strict?: boolean): Promise<string[]> {
  const authBase = getAuthBaseUrl(request);
  if (!authBase) {
    if (strict) throw new Error('[acl-utils] Auth base URL not configured (HIT_AUTH_URL / NEXT_PUBLIC_HIT_AUTH_URL or /api/proxy/auth).');
    return [];
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  const bearer = getBearerFromRequest(request);
  if (bearer) headers.Authorization = bearer;

  // Service token helps the proxy/module fetch config; safe to include if present.
  const serviceToken = process.env.HIT_SERVICE_TOKEN;
  if (serviceToken) headers['X-HIT-Service-Token'] = serviceToken;

  const res = await fetch(`${authBase}/me/groups`, { headers });
  if (!res.ok) {
    if (strict) throw new Error(`[acl-utils] GET ${authBase}/me/groups failed: ${res.status} ${res.statusText}`);
    return [];
  }

  const data = await res.json().catch(() => null);
  if (!Array.isArray(data)) {
    if (strict) throw new Error('[acl-utils] /me/groups returned a non-array response.');
    return [];
  }

  const ids: string[] = [];
  for (const row of data) {
    // Auth module uses `group_id` in MeGroupResponse.
    const gid = (row as any)?.group_id ?? (row as any)?.groupId ?? null;
    if (gid) ids.push(String(gid));
  }
  return ids;
}

async function fetchAuthAdminUserGroupIds(request: RequestLike, userEmail: string, strict?: boolean): Promise<string[]> {
  const authBase = getAuthBaseUrl(request);
  if (!authBase) {
    if (strict) throw new Error('[acl-utils] Auth base URL not configured (HIT_AUTH_URL / NEXT_PUBLIC_HIT_AUTH_URL or /api/proxy/auth).');
    return [];
  }
  const email = String(userEmail || '').trim().toLowerCase();
  if (!email) return [];

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Prefer service token for admin endpoints.
  const serviceToken = process.env.HIT_SERVICE_TOKEN;
  if (serviceToken) headers['X-HIT-Service-Token'] = serviceToken;

  // Also forward caller auth if present (useful in dev / when service token is not set).
  const bearer = getBearerFromRequest(request);
  if (bearer) headers.Authorization = bearer;

  const res = await fetch(`${authBase}/admin/users/${encodeURIComponent(email)}/groups`, { headers });
  if (!res.ok) {
    if (strict) throw new Error(`[acl-utils] GET ${authBase}/admin/users/{email}/groups failed: ${res.status} ${res.statusText}`);
    return [];
  }

  const data = await res.json().catch(() => null);
  if (!Array.isArray(data)) {
    if (strict) throw new Error('[acl-utils] /admin/users/{email}/groups returned a non-array response.');
    return [];
  }

  const ids: string[] = [];
  for (const row of data) {
    // Auth module uses `group_id` in UserGroupResponse.
    const gid = (row as any)?.group_id ?? (row as any)?.groupId ?? null;
    if (gid) ids.push(String(gid));
  }
  return ids;
}

/**
 * Resolve the current user's principals for ACL checks.
 *
 * Key behavior:
 * - Always includes userId + email + roles from the JWT claims.
 * - Optionally expands groups via auth module `/me/groups` (includes dynamic groups like "Everyone").
 * - Supports feature-pack-specific extra group sources.
 */
export async function resolveUserPrincipals(options: ResolveUserPrincipalsOptions): Promise<ResolvedUserPrincipals> {
  const {
    request,
    user,
    includeTokenGroups = true,
    includeAuthMeGroups = true,
    strict = false,
    extraGroupIds,
  } = options;

  const userId = String(user.sub || '').trim();
  const userEmailRaw = String(user.email || '').trim();
  // In some deployments the JWT may omit `email` but set `sub` to the email address.
  // Dynamic group evaluation in auth module is email-based, so recover it when possible.
  const userEmail =
    userEmailRaw ||
    (userId.includes('@') ? userId : '');
  const roles = uniqStrings(Array.isArray(user.roles) ? user.roles : []);

  const groupIds: string[] = [];
  if (includeTokenGroups) {
    groupIds.push(...(Array.isArray(user.groups) ? user.groups : []));
  }

  if (includeAuthMeGroups) {
    if (!request) {
      if (strict) {
        throw new Error('[acl-utils] Cannot resolve auth groups without a request (needed to reach /api/proxy/auth or forward auth headers).');
      }
      warnOnce('no_request', '[acl-utils] resolveUserPrincipals(): request not provided; dynamic groups will not be resolved.');
    } else {
      const bearer = getBearerFromRequest(request);
      const hasServiceToken = Boolean(process.env.HIT_SERVICE_TOKEN);
      if (!bearer && !hasServiceToken) {
        if (strict) {
          throw new Error('[acl-utils] Cannot authenticate to auth module for group resolution (no Authorization/ hit_token cookie and no HIT_SERVICE_TOKEN).');
        }
        warnOnce('no_auth_for_me_groups', '[acl-utils] resolveUserPrincipals(): no bearer/cookie auth and no HIT_SERVICE_TOKEN; dynamic groups may be missing.');
      }

      // /me/groups (user-auth) — best effort unless strict.
      try {
        groupIds.push(...(await fetchAuthMeGroupIds(request, strict)));
      } catch (e) {
        if (strict) throw e;
      }
    }
  }

  // Also include admin-resolved groups when we have a service token.
  //
  // Why:
  // - Dynamic groups ("Everyone", segments-backed groups) may require service/admin privileges
  //   during evaluation (auth module calls segments/metrics-core).
  // - Some deployments authenticate requests via non-`hit_token` cookies/proxy headers, which means
  //   `/me/groups` can return incomplete results even though the app can still authenticate the user.
  // - Historically, Vault used the admin endpoint with a service token, which is why group sharing
  //   worked there. We want that behavior consistently across feature packs.
  if (includeAuthMeGroups && request && userEmail) {
    const hasServiceToken = Boolean(process.env.HIT_SERVICE_TOKEN);
    if (!hasServiceToken) {
      // In many deployments dynamic group evaluation needs the service token path.
      warnOnce('no_service_token_admin_groups', '[acl-utils] resolveUserPrincipals(): HIT_SERVICE_TOKEN not set; admin-resolved dynamic groups (e.g. "Everyone") may be missing.');
    } else {
      try {
        groupIds.push(...(await fetchAuthAdminUserGroupIds(request, userEmail, strict)));
      } catch (e) {
        if (strict) throw e;
      }
    }
  }

  if (extraGroupIds) {
    try {
      groupIds.push(...(await extraGroupIds()));
    } catch (e) {
      if (strict) throw e;
    }
  }

  return {
    userId,
    userEmail,
    roles,
    groupIds: uniqStrings(groupIds),
  };
}


