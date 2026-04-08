export interface BouncingConfig {
  /** Base URL of your Bouncing server, e.g. "https://auth.myapp.com" */
  baseURL: string;
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
