import { useBouncingContext } from './provider.js';
import type { User } from './types.js';

/**
 * Returns the current user and loading state.
 * Must be used within a BouncingProvider.
 */
export function useUser(): { user: User | null; isLoading: boolean; signOut: () => void } {
  return useBouncingContext();
}
