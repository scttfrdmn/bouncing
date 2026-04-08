import { createRemoteJWKSet, jwtVerify, type JWTPayload, type KeyLike } from 'jose';
import type { Session } from '../types.js';

// JWKS cache: lazily refreshed when TTL expires — no background timers.
const jwksCache = new Map<string, { jwks: ReturnType<typeof createRemoteJWKSet>; fetchedAt: number }>();
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

/** Returns a cached (or fresh) JWKS verifier for the given server URL. */
function getJWKS(baseURL: string): ReturnType<typeof createRemoteJWKSet> {
  const url = `${baseURL}/.well-known/jwks.json`;
  const cached = jwksCache.get(url);
  if (cached != null && Date.now() - cached.fetchedAt < JWKS_TTL_MS) {
    return cached.jwks;
  }
  const jwks = createRemoteJWKSet(new URL(url));
  jwksCache.set(url, { jwks, fetchedAt: Date.now() });
  return jwks;
}

/** Clears the JWKS cache. Intended for use in tests only. */
export function _clearJwksCache(): void {
  jwksCache.clear();
}

/**
 * Verifies a Bouncing access token (EdDSA-signed JWT).
 * Returns a Session on success, null on any failure.
 */
export async function verifyAccessToken(token: string, baseURL: string): Promise<Session | null> {
  try {
    const jwks = getJWKS(baseURL);
    const { payload } = await jwtVerify(token, jwks, { algorithms: ['EdDSA'] });
    return payloadToSession(token, payload);
  } catch {
    return null;
  }
}

/**
 * Verifies a token against a known CryptoKey (no remote JWKS fetch).
 * Used in unit tests to validate session construction without network access.
 * @internal
 */
export async function _verifyTokenWithKey(token: string, key: KeyLike): Promise<Session | null> {
  try {
    const { payload } = await jwtVerify(token, key, { algorithms: ['EdDSA'] });
    return payloadToSession(token, payload);
  } catch {
    return null;
  }
}

/**
 * Calls /auth/refresh to rotate the refresh token and get a new access token.
 * Returns new tokens on success, null on failure.
 */
export async function refreshTokens(
  baseURL: string,
  refreshToken: string,
): Promise<{ accessToken: string; refreshToken: string } | null> {
  try {
    const resp = await fetch(`${baseURL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as { access_token: string; refresh_token: string };
    return { accessToken: data.access_token, refreshToken: data.refresh_token };
  } catch {
    return null;
  }
}

function payloadToSession(token: string, payload: JWTPayload): Session {
  return {
    user: {
      id: payload.sub ?? '',
      email: (payload['email'] as string | undefined) ?? '',
      name: (payload['name'] as string | undefined) ?? '',
      avatarUrl: payload['avatar_url'] as string | undefined,
      roles: (payload['roles'] as string[] | undefined) ?? [],
      permissions: (payload['permissions'] as string[] | undefined) ?? [],
      orgId: payload['org_id'] as string | undefined,
    },
    accessToken: token,
    expiresAt: ((payload.exp ?? 0) as number) * 1000,
  };
}
