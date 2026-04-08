import type { BouncingConfig, Session, User } from '../types.js';
import { verifyAccessToken, refreshTokens } from './auth.js';
import { createAdminClient, type BouncingAdminClient } from './admin.js';

export type { BouncingConfig, Session, User };

export interface BouncingInstance {
  /**
   * Returns the current session by verifying the access token cookie.
   * Automatically refreshes using the refresh token if the access token is expired.
   * Returns null when the user is not authenticated.
   *
   * Must be called from a Next.js Server Component or Route Handler.
   */
  auth(): Promise<Session | null>;

  /**
   * Like auth(), but throws if the user is not authenticated.
   * Use in routes/pages that require authentication.
   */
  currentUser(): Promise<User>;

  /** Management API client for server-side admin operations. */
  bouncingAdmin: BouncingAdminClient;
}

/**
 * Creates a Bouncing instance configured with the given options.
 *
 * @example
 * ```ts
 * // auth.ts
 * import { createBouncing } from '@bouncing/next';
 * export const { auth, currentUser, bouncingAdmin } = createBouncing({
 *   baseURL: process.env.BOUNCING_URL!,
 *   apiKey: process.env.BOUNCING_API_KEY,
 * });
 * ```
 */
export function createBouncing(config: BouncingConfig): BouncingInstance {
  const admin = createAdminClient(config);

  async function auth(): Promise<Session | null> {
    // Dynamic import avoids errors when used outside Next.js (e.g., in tests).
    const { cookies } = await import('next/headers');
    const cookieStore = await cookies();

    const accessToken = cookieStore.get('bouncing_access')?.value;
    if (accessToken) {
      const session = await verifyAccessToken(accessToken, config.baseURL);
      if (session != null && session.expiresAt > Date.now()) {
        return session;
      }
    }

    // Access token missing or expired — try refresh.
    const rt = cookieStore.get('bouncing_refresh')?.value;
    if (rt == null) return null;

    const tokens = await refreshTokens(config.baseURL, rt);
    if (tokens == null) return null;

    return verifyAccessToken(tokens.accessToken, config.baseURL);
  }

  async function currentUser(): Promise<User> {
    const session = await auth();
    if (session == null) throw new Error('Not authenticated');
    return session.user;
  }

  return { auth, currentUser, bouncingAdmin: admin };
}
