import type { Env, User, UserWithoutPassword } from './types';

const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 64;
const SALT_LENGTH = 32;
const TOKEN_EXPIRY = '7d';

function base64UrlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    key,
    KEY_LENGTH * 8
  );
  const saltB64 = base64UrlEncode(salt);
  const hashB64 = base64UrlEncode(hash);
  return `${PBKDF2_ITERATIONS}:${saltB64}:${hashB64}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [iterStr, saltB64, hashB64] = stored.split(':');
  const iterations = parseInt(iterStr, 10);
  const salt = base64UrlDecode(saltB64);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key,
    KEY_LENGTH * 8
  );
  const expectedB64 = base64UrlEncode(hash);
  return hashB64 === expectedB64;
}

export async function generateToken(user: UserWithoutPassword, env: Env): Promise<string> {
  return generateJWT({ sub: String(user.id), email: user.email, name: user.name, role: user.role }, env);
}

export async function generateSessionToken(user: { id: string; email: string; name: string; team: string }, env: Env): Promise<string> {
  return generateJWT({ sub: user.id, email: user.email, name: user.name, role: user.team }, env);
}

async function generateJWT(payload: { sub: string; email: string; name: string; role: string }, env: Env): Promise<string> {
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        role: payload.role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
      })
    )
  );
  const signature = await signJWT(`${header}.${body}`, env.JWT_SECRET);
  return `${header}.${body}.${signature}`;
}

async function signJWT(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64UrlEncode(sig);
}

export async function verifyToken(token: string, env: Env): Promise<any | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const expectedSig = await signJWT(`${parts[0]}.${parts[1]}`, env.JWT_SECRET);
    if (parts[2] !== expectedSig) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;

    return { id: payload.sub, email: payload.email, name: payload.name || '', role: payload.role };
  } catch {
    return null;
  }
}

export function generateKeyCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const rand = crypto.getRandomValues(new Uint8Array(12));
  const parts: string[] = [];
  for (let i = 0; i < 12; i++) {
    parts.push(chars[rand[i] % chars.length]);
  }
  return `DMK-${parts.slice(0, 4).join('')}-${parts.slice(4, 8).join('')}-${parts.slice(8, 12).join('')}`;
}

export function generateChallenge(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const rand = crypto.getRandomValues(new Uint8Array(16));
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars[rand[i] % chars.length];
  }
  return `chal_${result}`;
}

export async function signChallenge(key: string, secret: string, ttlSec: number): Promise<string> {
  const expires = Math.floor(Date.now() / 1000) + ttlSec;
  const payload = `${key}:${expires}`;
  const sig = await signJWT(payload, secret);
  return `${payload}:${sig}`;
}

export async function verifyChallenge(signed: string, secret: string): Promise<string | null> {
  const parts = signed.split(':');
  if (parts.length < 3) return null;
  const key = parts[0];
  const expires = parseInt(parts[1], 10);
  const sig = parts.slice(2).join(':');
  const expectedSig = await signJWT(`${key}:${expires}`, secret);
  if (sig !== expectedSig) return null;
  if (expires < Math.floor(Date.now() / 1000)) return null;
  return key;
}
