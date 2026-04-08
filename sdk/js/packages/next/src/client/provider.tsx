'use client';

import React, { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import type { Session, User } from '../types.js';

interface BouncingContextValue {
  session: Session | null;
  user: User | null;
  isLoading: boolean;
}

const BouncingContext = createContext<BouncingContextValue>({
  session: null,
  user: null,
  isLoading: true,
});

export interface BouncingProviderProps {
  children: ReactNode;
  /**
   * Pre-hydrated session from a Server Component.
   * Passing this avoids an extra /auth/me round-trip on mount.
   */
  initialSession?: Session | null;
  /** Base URL of your Bouncing server */
  baseURL: string;
}

/**
 * Wraps your app (or a subtree) to provide the current user via context.
 * Place near the root of your layout.
 */
export function BouncingProvider({ children, initialSession, baseURL }: BouncingProviderProps) {
  const [session, setSession] = useState<Session | null>(initialSession ?? null);
  const [isLoading, setIsLoading] = useState(initialSession === undefined);

  useEffect(() => {
    if (initialSession !== undefined) {
      setIsLoading(false);
      return;
    }
    fetch(`${baseURL}/auth/me`, { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data: User | null) => {
        if (data != null) {
          setSession({ user: data, accessToken: '', expiresAt: 0 });
        }
      })
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, [baseURL, initialSession]);

  return (
    <BouncingContext.Provider value={{ session, user: session?.user ?? null, isLoading }}>
      {children}
    </BouncingContext.Provider>
  );
}

/** @internal */
export function useBouncingContext(): BouncingContextValue {
  return useContext(BouncingContext);
}
