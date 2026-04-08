import type { BouncingConfig, User } from '../types.js';

export interface InviteUserRequest {
  email: string;
  name?: string;
  role?: string;
}

export interface BouncingAdminClient {
  listUsers(opts?: { page?: number; perPage?: number; q?: string }): Promise<{ users: User[]; total: number }>;
  inviteUser(req: InviteUserRequest): Promise<{ id: string; email: string; status: string }>;
  deleteUser(id: string): Promise<void>;
}

export function createAdminClient(config: BouncingConfig): BouncingAdminClient {
  const apiKey = config.apiKey ?? '';
  const authHeader = `Bearer ${apiKey}`;

  async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
    const resp = await fetch(`${config.baseURL}${path}`, {
      ...init,
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
        ...init?.headers,
      },
    });
    if (!resp.ok) {
      const err = (await resp.json().catch(() => ({}))) as { error?: { message?: string } };
      throw new Error(err.error?.message ?? `HTTP ${resp.status}`);
    }
    return resp.json() as Promise<T>;
  }

  return {
    async listUsers(opts = {}) {
      const q = new URLSearchParams();
      if (opts.page != null) q.set('page', String(opts.page));
      if (opts.perPage != null) q.set('per_page', String(opts.perPage));
      if (opts.q != null) q.set('q', opts.q);
      const qs = q.toString();
      return apiFetch<{ users: User[]; total: number }>(`/manage/users${qs ? `?${qs}` : ''}`);
    },

    async inviteUser(req) {
      return apiFetch<{ id: string; email: string; status: string }>('/manage/users/invite', {
        method: 'POST',
        body: JSON.stringify(req),
      });
    },

    async deleteUser(id) {
      await apiFetch<unknown>(`/manage/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
    },
  };
}
