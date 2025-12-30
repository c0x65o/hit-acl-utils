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
   * Optional additional group id sources (feature-pack specific), e.g. vault's own group membership tables.
   */
  extraGroupIds?: () => Promise<string[]>;
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

async function fetchAuthMeGroupIds(request: RequestLike): Promise<string[]> {
  const authBase = getAuthBaseUrl(request);
  if (!authBase) return [];

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  const bearer = getBearerFromRequest(request);
  if (bearer) headers.Authorization = bearer;

  // Service token helps the proxy/module fetch config; safe to include if present.
  const serviceToken = process.env.HIT_SERVICE_TOKEN;
  if (serviceToken) headers['X-HIT-Service-Token'] = serviceToken;

  const res = await fetch(`${authBase}/me/groups`, { headers });
  if (!res.ok) return [];

  const data = await res.json().catch(() => null);
  if (!Array.isArray(data)) return [];

  const ids: string[] = [];
  for (const row of data) {
    // Auth module uses `group_id` in MeGroupResponse.
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
    extraGroupIds,
  } = options;

  const userId = String(user.sub || '').trim();
  const userEmail = String(user.email || '').trim();
  const roles = uniqStrings(Array.isArray(user.roles) ? user.roles : []);

  const groupIds: string[] = [];
  if (includeTokenGroups) {
    groupIds.push(...(Array.isArray(user.groups) ? user.groups : []));
  }

  if (includeAuthMeGroups && request) {
    try {
      groupIds.push(...(await fetchAuthMeGroupIds(request)));
    } catch {
      // Best effort only; callers should still function on JWT-only groups.
    }
  }

  if (extraGroupIds) {
    try {
      groupIds.push(...(await extraGroupIds()));
    } catch {
      // Best effort
    }
  }

  return {
    userId,
    userEmail,
    roles,
    groupIds: uniqStrings(groupIds),
  };
}


