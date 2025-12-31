function uniqStrings(xs) {
    const out = [];
    const seen = new Set();
    for (const raw of xs) {
        const s = String(raw || '').trim();
        if (!s)
            continue;
        if (seen.has(s))
            continue;
        seen.add(s);
        out.push(s);
    }
    return out;
}
function baseUrlFromRequest(request) {
    const proto = request.headers.get('x-forwarded-proto') ||
        request.nextUrl?.protocol?.replace(':', '') ||
        'http';
    const host = request.headers.get('x-forwarded-host') ||
        request.headers.get('host') ||
        request.nextUrl?.host ||
        '';
    return `${proto}://${host}`;
}
function getBearerFromRequest(request) {
    const authz = request.headers.get('authorization');
    if (authz?.startsWith('Bearer '))
        return authz;
    const cookie = request.headers.get('cookie') || '';
    if (!cookie)
        return null;
    const parts = cookie.split(';').map((c) => c.trim());
    for (const p of parts) {
        const eqIdx = p.indexOf('=');
        if (eqIdx <= 0)
            continue;
        const name = p.slice(0, eqIdx);
        const value = p.slice(eqIdx + 1);
        if (name === 'hit_token' && value) {
            return `Bearer ${value}`;
        }
    }
    return null;
}
function getAuthBaseUrl(request) {
    // Prefer direct module URL (server-side)
    const direct = process.env.HIT_AUTH_URL || process.env.NEXT_PUBLIC_HIT_AUTH_URL;
    if (direct)
        return direct.replace(/\/$/, '');
    // Fallback to app-local proxy route
    if (request) {
        return `${baseUrlFromRequest(request)}/api/proxy/auth`;
    }
    return null;
}
async function fetchAuthMeGroupIds(request) {
    const authBase = getAuthBaseUrl(request);
    if (!authBase)
        return [];
    const headers = {
        'Content-Type': 'application/json',
    };
    const bearer = getBearerFromRequest(request);
    if (bearer)
        headers.Authorization = bearer;
    // Service token helps the proxy/module fetch config; safe to include if present.
    const serviceToken = process.env.HIT_SERVICE_TOKEN;
    if (serviceToken)
        headers['X-HIT-Service-Token'] = serviceToken;
    const res = await fetch(`${authBase}/me/groups`, { headers });
    if (!res.ok)
        return [];
    const data = await res.json().catch(() => null);
    if (!Array.isArray(data))
        return [];
    const ids = [];
    for (const row of data) {
        // Auth module uses `group_id` in MeGroupResponse.
        const gid = row?.group_id ?? row?.groupId ?? null;
        if (gid)
            ids.push(String(gid));
    }
    return ids;
}

async function fetchAuthAdminUserGroupIds(request, userEmail) {
    const authBase = getAuthBaseUrl(request);
    if (!authBase)
        return [];
    const email = String(userEmail || '').trim().toLowerCase();
    if (!email)
        return [];
    const headers = {
        'Content-Type': 'application/json',
    };
    // Prefer service token for admin endpoints.
    const serviceToken = process.env.HIT_SERVICE_TOKEN;
    if (serviceToken)
        headers['X-HIT-Service-Token'] = serviceToken;
    // Also forward caller auth if present (useful in dev / when service token is not set).
    const bearer = getBearerFromRequest(request);
    if (bearer)
        headers.Authorization = bearer;
    const res = await fetch(`${authBase}/admin/users/${encodeURIComponent(email)}/groups`, { headers });
    if (!res.ok)
        return [];
    const data = await res.json().catch(() => null);
    if (!Array.isArray(data))
        return [];
    const ids = [];
    for (const row of data) {
        // Auth module uses `group_id` in UserGroupResponse.
        const gid = row?.group_id ?? row?.groupId ?? null;
        if (gid)
            ids.push(String(gid));
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
export async function resolveUserPrincipals(options) {
    const { request, user, includeTokenGroups = true, includeAuthMeGroups = true, extraGroupIds, } = options;
    const userId = String(user.sub || '').trim();
    const userEmail = String(user.email || '').trim();
    const roles = uniqStrings(Array.isArray(user.roles) ? user.roles : []);
    const groupIds = [];
    if (includeTokenGroups) {
        groupIds.push(...(Array.isArray(user.groups) ? user.groups : []));
    }
    if (includeAuthMeGroups && request) {
        try {
            groupIds.push(...(await fetchAuthMeGroupIds(request)));
        }
        catch {
            // Best effort only; callers should still function on JWT-only groups.
        }
    }

    // Also include admin-resolved groups when we have a service token.
    // This restores dynamic groups like "Everyone" in deployments where segment evaluation
    // requires service/admin privileges.
    if (includeAuthMeGroups && request && userEmail) {
        try {
            const hasServiceToken = Boolean(process.env.HIT_SERVICE_TOKEN);
            if (hasServiceToken) {
                groupIds.push(...(await fetchAuthAdminUserGroupIds(request, userEmail)));
            }
        }
        catch {
            // Best effort
        }
    }
    if (extraGroupIds) {
        try {
            groupIds.push(...(await extraGroupIds()));
        }
        catch {
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
