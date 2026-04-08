import { describe, it, expect, vi, afterEach } from 'vitest';
import { createAdminClient } from './admin.js';

const config = { baseURL: 'http://localhost:8080', apiKey: 'bnc_api_test' };

describe('bouncingAdmin', () => {
  afterEach(() => vi.restoreAllMocks());

  it('listUsers sends correct request', async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      json: async () => ({ users: [], total: 0 }),
    } as Response));
    vi.stubGlobal('fetch', mockFetch);

    const admin = createAdminClient(config);
    await admin.listUsers({ page: 2, perPage: 10, q: 'alice' });

    const [url, init] = mockFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain('/manage/users');
    expect(url).toContain('page=2');
    expect(url).toContain('per_page=10');
    expect(url).toContain('q=alice');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer bnc_api_test');
  });

  it('inviteUser sends correct body', async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      json: async () => ({ id: 'u1', email: 'a@b.com', status: 'pending' }),
    } as Response));
    vi.stubGlobal('fetch', mockFetch);

    const admin = createAdminClient(config);
    const result = await admin.inviteUser({ email: 'a@b.com', role: 'editor' });

    const [url, init] = mockFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain('/manage/users/invite');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toMatchObject({ email: 'a@b.com', role: 'editor' });
    expect(result.status).toBe('pending');
  });

  it('deleteUser uses DELETE method', async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      json: async () => ({ deleted: true }),
    } as Response));
    vi.stubGlobal('fetch', mockFetch);

    const admin = createAdminClient(config);
    await admin.deleteUser('user-abc');

    const [url, init] = mockFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain('/manage/users/user-abc');
    expect(init.method).toBe('DELETE');
  });

  it('throws on API error response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: false,
      status: 404,
      json: async () => ({ error: { message: 'user not found' } }),
    } as Response)));

    const admin = createAdminClient(config);
    await expect(admin.deleteUser('missing')).rejects.toThrow('user not found');
  });
});
