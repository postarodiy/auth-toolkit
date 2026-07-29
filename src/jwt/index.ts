/**
 * Edge-safe JWT and cookie primitives, built on jose. No Node-only APIs,
 * so this module can run in any JS runtime including edge/serverless.
 */

import { SignJWT, jwtVerify, type JWTPayload } from 'jose';

export interface JwtSignOptions {
  secret: string;
  algorithm?: 'HS256' | 'HS384' | 'HS512';
  expiresIn?: string | number;
  /** true generates a random UUID; pass a function for a custom id source. */
  jwtId?: boolean | (() => string);
}

export interface JwtVerifyOptions {
  secret: string;
  /**
   * Algorithms accepted at verification time. Defaults to ['HS256'].
   * Always pass this explicitly if you sign with a non-default algorithm,
   * a mismatch here is what stops algorithm-confusion attacks.
   */
  algorithms?: string[];
}

function encodeSecret(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

export async function signJwt<TPayload extends Record<string, unknown>>(
  payload: TPayload,
  options: JwtSignOptions
): Promise<string> {
  const algorithm = options.algorithm ?? 'HS256';
  let jwt = new SignJWT(payload as JWTPayload)
    .setProtectedHeader({ alg: algorithm })
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ?? '1h');

  if (options.jwtId) {
    const jti = typeof options.jwtId === 'function' ? options.jwtId() : crypto.randomUUID();
    jwt = jwt.setJti(jti);
  }

  return jwt.sign(encodeSecret(options.secret));
}

/** Never throws; returns null for any invalid, expired, or tampered token. */
export async function verifyJwt<TPayload extends Record<string, unknown> = Record<string, unknown>>(
  token: string,
  options: JwtVerifyOptions
): Promise<(TPayload & { iat: number; exp: number }) | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, encodeSecret(options.secret), {
      algorithms: options.algorithms ?? ['HS256'],
    });
    return payload as unknown as TPayload & { iat: number; exp: number };
  } catch {
    return null;
  }
}

export interface CookieConfig {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'lax' | 'strict' | 'none';
  maxAge: number;
  path: string;
}

export interface BuildAuthCookieOptions {
  cookieName: string;
  /** Caller computes this from their own deployment/HTTPS detection logic. */
  secure: boolean;
  maxAgeSeconds: number;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
}

export function buildSessionCookie(token: string, options: BuildAuthCookieOptions): CookieConfig {
  return {
    name: options.cookieName,
    value: token,
    httpOnly: true,
    secure: options.secure,
    sameSite: options.sameSite ?? 'lax',
    maxAge: options.maxAgeSeconds,
    path: options.path ?? '/',
  };
}

export function buildClearCookie(options: Omit<BuildAuthCookieOptions, 'maxAgeSeconds'>): CookieConfig {
  return {
    name: options.cookieName,
    value: '',
    httpOnly: true,
    secure: options.secure,
    sameSite: options.sameSite ?? 'lax',
    maxAge: 0,
    path: options.path ?? '/',
  };
}
