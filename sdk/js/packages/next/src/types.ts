export interface BouncingConfig {
  /** Base URL of your Bouncing server, e.g. "https://auth.myapp.com" */
  baseURL: string;
  /** Management API key (bnc_api_...) — required for bouncingAdmin */
  apiKey?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  avatarUrl?: string;
  roles: string[];
  permissions: string[];
  orgId?: string;
}

export interface Session {
  user: User;
  /** Raw JWT access token */
  accessToken: string;
  /** Expiry timestamp in milliseconds */
  expiresAt: number;
}
