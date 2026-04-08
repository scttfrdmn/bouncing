import { describe, it, expect, vi, afterEach } from 'vitest';
import { refreshTokens, _verifyTokenWithKey } from './auth.js';
import { SignJWT, generateKeyPair, type KeyLike } from 'jose';

// Helpers ─────────────────────────────────────────────────────────────────────

async function makeTestKey() {
  return generateKeyPair('EdDSA', { crv: 'Ed25519' });
}

async function signToken(
  privateKey: KeyLike,
  claims: Record<string, unknown> = {},
  exp?: number,
) {
  const expTime = exp ?? Math.floor(Date.now() / 1000) + 900;
  return new SignJWT({
    sub: 'user-001',
    email: 'test@example.com',
    name: 'Test User',
    roles: ['admin'],
    permissions: ['*'],
    ...claims,
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setExpirationTime(expTime)
    .sign(privateKey);
}

// _verifyTokenWithKey ─────────────────────────────────────────────────────────
// Tests JWT parsing and session construction without JWKS remote fetch.

describe('_verifyTokenWithKey', () => {
  it('returns a session with correct fields for a valid token', async () => {
    const { privateKey, publicKey } = await makeTestKey();
    const token = await signToken(privateKey);

    const session = await _verifyTokenWithKey(token, publicKey);

    expect(session).not.toBeNull();
    expect(session?.user.id).toBe('user-001');
    expect(session?.user.email).toBe('test@example.com');
    expect(session?.user.name).toBe('Test User');
    expect(session?.user.roles).toEqual(['admin']);
    expect(session?.user.permissions).toEqual(['*']);
    expect(session?.accessToken).toBe(token);
    expect(session?.expiresAt).toBeGreaterThan(Date.now());
  });

  it('returns null for an expired token', async () => {
    const { privateKey, publicKey } = await makeTestKey();
    // Pass expiry in the past as the third parameter (not in claims object).
    const token = await signToken(privateKey, {}, Math.floor(Date.now() / 1000) - 5);
    const session = await _verifyTokenWithKey(token, publicKey);
    expect(session).toBeNull();
  });

  it('returns null when signed with a different key', async () => {
    const { privateKey } = await makeTestKey();
    const { publicKey: wrongKey } = await makeTestKey();
    const token = await signToken(privateKey);
    const session = await _verifyTokenWithKey(token, wrongKey);
    expect(session).toBeNull();
  });

  it('returns null for an empty string', async () => {
    const { publicKey } = await makeTestKey();
    const session = await _verifyTokenWithKey('', publicKey);
    expect(session).toBeNull();
  });

  it('includes optional fields when present', async () => {
    const { privateKey, publicKey } = await makeTestKey();
    const token = await signToken(privateKey, {
      avatar_url: 'https://example.com/avatar.jpg',
      org_id: 'org-001',
    });
    const session = await _verifyTokenWithKey(token, publicKey);
    expect(session?.user.avatarUrl).toBe('https://example.com/avatar.jpg');
    expect(session?.user.orgId).toBe('org-001');
  });
});

// refreshTokens ───────────────────────────────────────────────────────────────

describe('refreshTokens', () => {
  afterEach(() => vi.restoreAllMocks());

  it('returns new tokens on success', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ access_token: 'new_access', refresh_token: 'new_refresh' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    )));

    const result = await refreshTokens('http://localhost:8080', 'bnc_rt_old');
    expect(result?.accessToken).toBe('new_access');
    expect(result?.refreshToken).toBe('new_refresh');
  });

  it('returns null when the server returns a non-ok status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: { message: 'token revoked' } }),
      { status: 401 },
    )));

    const result = await refreshTokens('http://localhost:8080', 'stale_token');
    expect(result).toBeNull();
  });

  it('returns null on network error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network error'); }));
    const result = await refreshTokens('http://localhost:8080', 'any');
    expect(result).toBeNull();
  });

  it('sends the refresh token in the request body', async () => {
    const mockFetch = vi.fn(async () => new Response(
      JSON.stringify({ access_token: 'at', refresh_token: 'rt' }),
      { status: 200 },
    ));
    vi.stubGlobal('fetch', mockFetch);

    await refreshTokens('http://localhost:8080', 'bnc_rt_test123');

    const [url, init] = mockFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://localhost:8080/auth/refresh');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ refresh_token: 'bnc_rt_test123' });
  });
});
