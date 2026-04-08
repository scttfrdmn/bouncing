'use client';

import React, { useState } from 'react';
import { useBouncingContext } from './provider.js';

export interface UserButtonProps {
  /** Base URL of your Bouncing server (used to construct the logout URL) */
  baseURL: string;
}

/**
 * Renders an avatar button that opens a dropdown with user info and a sign-out link.
 * Returns null when no user is signed in.
 */
export function UserButton({ baseURL }: UserButtonProps) {
  const { user } = useBouncingContext();
  const [open, setOpen] = useState(false);

  if (user == null) return null;

  const initials = user.name.trim()
    ? user.name
        .trim()
        .split(/\s+/)
        .map((n) => n[0] ?? '')
        .slice(0, 2)
        .join('')
        .toUpperCase()
    : user.email.slice(0, 2).toUpperCase();

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label="User menu"
        aria-expanded={open}
        style={{
          width: 36,
          height: 36,
          borderRadius: '50%',
          background: '#6366f1',
          color: '#fff',
          border: 'none',
          cursor: 'pointer',
          fontWeight: 600,
          fontSize: 14,
          padding: 0,
          overflow: 'hidden',
        }}
      >
        {user.avatarUrl ? (
          <img
            src={user.avatarUrl}
            alt={user.name}
            style={{ width: 36, height: 36, display: 'block' }}
          />
        ) : (
          initials
        )}
      </button>

      {open && (
        <div
          role="menu"
          style={{
            position: 'absolute',
            right: 0,
            top: 44,
            background: '#fff',
            border: '1px solid #e5e7eb',
            borderRadius: 8,
            padding: '4px 0',
            minWidth: 200,
            boxShadow: '0 4px 16px rgba(0,0,0,.12)',
            zIndex: 50,
          }}
        >
          <div style={{ padding: '10px 16px', borderBottom: '1px solid #f3f4f6' }}>
            {user.name && <div style={{ fontWeight: 600, fontSize: 14 }}>{user.name}</div>}
            <div style={{ fontSize: 13, color: '#6b7280' }}>{user.email}</div>
          </div>
          <a
            href={`${baseURL}/auth/logout`}
            role="menuitem"
            style={{ display: 'block', padding: '8px 16px', color: '#374151', textDecoration: 'none', fontSize: 14 }}
          >
            Sign out
          </a>
        </div>
      )}
    </div>
  );
}
