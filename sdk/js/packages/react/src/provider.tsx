import React, { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import type { User, BouncingConfig } from './types.js';

interface BouncingContextValue {
  user: User | null;
  isLoading: boolean;
  signOut: () => void;
}

const BouncingContext = createContext<BouncingContextValue>({
  user: null,
  isLoading: true,
  signOut: () => {},
});

export interface BouncingProviderProps {
  children: ReactNode;
  config: BouncingConfig;
}

/**
 * Wraps your React SPA to provide the current user via context.
 * Fetches user info from /auth/me on mount.
 */
export function BouncingProvider({ children, config }: BouncingProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch(`${config.baseURL}/auth/me`, { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data: User | null) => setUser(data))
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, [config.baseURL]);

  function signOut() {
    window.location.href = `${config.baseURL}/auth/logout`;
  }

  return (
    <BouncingContext.Provider value={{ user, isLoading, signOut }}>
      {children}
    </BouncingContext.Provider>
  );
}

export function useBouncingContext(): BouncingContextValue {
  return useContext(BouncingContext);
}
