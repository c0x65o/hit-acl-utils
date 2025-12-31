export type PrincipalType = 'user' | 'group' | 'role';
/**
 * Minimal request shape needed for principal expansion.
 * Compatible with Next.js `NextRequest` (and similar request abstractions).
 */
export interface RequestLike {
    headers: {
        get(name: string): string | null;
    };
    nextUrl?: {
        protocol?: string;
        host?: string;
    };
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
/**
 * Resolve the current user's principals for ACL checks.
 *
 * Key behavior:
 * - Always includes userId + email + roles from the JWT claims.
 * - Optionally expands groups via auth module `/me/groups` (includes dynamic groups like "Everyone").
 * - Supports feature-pack-specific extra group sources.
 */
export declare function resolveUserPrincipals(options: ResolveUserPrincipalsOptions): Promise<ResolvedUserPrincipals>;
