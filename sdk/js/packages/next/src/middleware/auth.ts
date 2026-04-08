import type { BouncingConfig } from '../types.js';
import { verifyAccessToken } from '../server/auth.js';

type NextMiddlewareReturn = Response | undefined;

/**
 * Creates a Next.js edge middleware that protects routes behind authentication.
 * Redirects unauthenticated requests to the login page.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { withAuth } from '@bouncing/next/middleware';
 * export default withAuth({ baseURL: process.env.BOUNCING_URL! });
 * export const config = { matcher: ['/dashboard/:path*'] };
 * ```
 */
export function withAuth(
  config: BouncingConfig,
  options?: { loginPath?: string },
): (request: Request) => Promise<NextMiddlewareReturn> {
  const loginPath = options?.loginPath ?? '/auth/login';

  return async function middleware(request: Request): Promise<NextMiddlewareReturn> {
    const { NextResponse } = await import('next/server');
    const req = request as import('next/server').NextRequest;

    const accessToken = req.cookies.get('bouncing_access')?.value;
    if (accessToken != null) {
      const session = await verifyAccessToken(accessToken, config.baseURL);
      if (session != null && session.expiresAt > Date.now()) {
        return NextResponse.next();
      }
    }

    const loginURL = new URL(loginPath, req.url);
    loginURL.searchParams.set('redirect', req.nextUrl.pathname);
    return NextResponse.redirect(loginURL);
  };
}
