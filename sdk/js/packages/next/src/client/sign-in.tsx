'use client';

import React from 'react';

const PROVIDER_LABELS: Record<string, string> = {
  google: 'Sign in with Google',
  github: 'Sign in with GitHub',
  microsoft: 'Sign in with Microsoft',
  apple: 'Sign in with Apple',
};

export interface SignInProps {
  /** List of provider names returned by GET /auth/providers */
  providers: string[];
  /** Base URL of your Bouncing server */
  baseURL: string;
  className?: string;
}

/**
 * Renders sign-in buttons for each configured OAuth provider.
 *
 * @example
 * ```tsx
 * // Fetch providers server-side and pass to client:
 * const { providers } = await fetch(`${BOUNCING_URL}/auth/providers`).then(r => r.json());
 * return <SignIn providers={providers} baseURL={BOUNCING_URL} />;
 * ```
 */
export function SignIn({ providers, baseURL, className }: SignInProps) {
  return (
    <div className={className}>
      {providers.map((p) => (
        <a
          key={p}
          href={`${baseURL}/auth/oauth/${encodeURIComponent(p)}`}
          style={{ display: 'block', margin: '8px 0', padding: '10px 16px', border: '1px solid #e5e7eb', borderRadius: 8, textDecoration: 'none', color: '#111827' }}
        >
          {PROVIDER_LABELS[p] ?? `Sign in with ${p}`}
        </a>
      ))}
    </div>
  );
}
