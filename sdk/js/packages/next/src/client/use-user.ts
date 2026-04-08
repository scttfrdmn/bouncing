'use client';

import { useBouncingContext } from './provider.js';
import type { User } from '../types.js';

/**
 * Returns the current user and loading state from the nearest BouncingProvider.
 *
 * @example
 * ```tsx
 * function Avatar() {
 *   const { user, isLoading } = useUser();
 *   if (isLoading) return <Spinner />;
 *   if (!user) return <SignIn providers={['google']} baseURL="..." />;
 *   return <img src={user.avatarUrl} alt={user.name} />;
 * }
 * ```
 */
export function useUser(): { user: User | null; isLoading: boolean } {
  const { user, isLoading } = useBouncingContext();
  return { user, isLoading };
}
