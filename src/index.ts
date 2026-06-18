import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { DB } from './db';
import { hashPassword, verifyPassword, generateToken, generateSessionToken, verifyToken, generateKeyCode, generateChallenge, signChallenge, verifyChallenge } from './crypto';

const app = new Hono<{ Bindings: Env; Variables: { user: any } }>();

app.use('/*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'OPTIONS'], allowHeaders: ['Content-Type', 'Authorization'] }));

// ── Health check ──
app.get('/api/health', (c) => c.json({ status: 'ok', service: 'dealmaker-api' }));

// ── Session endpoints ──
app.post('/api/auth/session', async (c) => {
  try {
    const { email } = await c.req.json();
    if (!email) {
      return c.json({ authenticated: false, devMode: false, error: 'email required' }, 400);
    }

    const db = new DB(c.env);
    const rows = await db.db.prepare("SELECT id, email, name, team FROM users WHERE LOWER(email) = LOWER(?) AND active = 1").bind(email).first<{ id: string; email: string; name: string; team: string }>();
    if (!rows) {
      return c.json({ authenticated: false, devMode: false, error: 'user not found' }, 401);
    }

    const sessionUser = {
      id: rows.id,
      organizationId: 'org_demo',
      organizationName: 'DealMaker Demo',
      email: rows.email,
      name: rows.name,
      team: rows.team as 'sales' | 'business',
      canApproveHighRisk: rows.team === 'business',
    };
    const token = await generateSessionToken(sessionUser, c.env);
    return c.json({ authenticated: true, user: sessionUser, devMode: false, token });
  } catch (e: any) {
    return c.json({ authenticated: false, devMode: false, error: e?.message || 'login failed' }, 500);
  }
});

app.get('/api/auth/session', async (c) => {
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ authenticated: false, devMode: false });
  }
  const payload = await verifyToken(auth.slice(7), c.env);
  if (!payload) {
    return c.json({ authenticated: false, devMode: false });
  }
  const team = payload.role === 'admin' ? 'business' : (payload.role || 'sales');
  const user = {
    id: String(payload.id),
    organizationId: 'org_demo',
    organizationName: 'DealMaker Demo',
    email: payload.email,
    name: payload.name,
    team,
    canApproveHighRisk: team === 'business',
  };
  return c.json({ authenticated: true, user, devMode: true });
});

app.delete('/api/auth/session', async (c) => {
  return c.json({ authenticated: false, devMode: false });
});

// ── Deals (stub — returns empty list for now) ──
app.get('/api/deals', async (c) => {
  return c.json({ deals: [] });
});

// ── Get a signed challenge token (crypto-based, no DB needed) ──
app.post('/api/auth/challenge', async (c) => {
  try {
    const key = generateChallenge();
    const signed = await signChallenge(key, c.env.JWT_SECRET, 600);
    return c.json({ key: signed });
  } catch (e: any) {
    return c.json({ error: 'challenge generation failed' }, 500);
  }
});

// ── First admin setup (only works if no admin exists yet) ──
app.post('/api/auth/setup', async (c) => {
  try {
    const { email, password, name, key } = await c.req.json();
    if (!email || !password || !key) {
      return c.json({ error: 'email, password, and challenge key are required' }, 400);
    }
    if (password.length < 8) {
      return c.json({ error: 'password must be at least 8 characters' }, 400);
    }

    const chalOk = await verifyChallenge(key, c.env.JWT_SECRET);
    if (!chalOk) {
      return c.json({ error: 'invalid or expired challenge key — refresh the page' }, 400);
    }

    const passwordHash = await hashPassword(password);
    const user = await db.createUser(email, passwordHash, name || 'Admin', 'admin');
    const token = await generateToken({ id: user.id, email: user.email, name: user.name, role: user.role }, c.env);

    return c.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } }, 201);
  } catch (e: any) {
    return c.json({ error: e?.message || 'setup failed' }, 500);
  }
});

// ── Login (requires challenge key from /api/auth/challenge) ──
app.post('/api/auth/login', async (c) => {
  try {
    const { email, password, key } = await c.req.json();
    if (!email || !password || !key) {
      return c.json({ error: 'email, password, and challenge key are required' }, 400);
    }

    const chalOk = await verifyChallenge(key, c.env.JWT_SECRET);
    if (!chalOk) {
      return c.json({ error: 'invalid or expired challenge key — refresh the page' }, 400);
    }

    const db = new DB(c.env);
    const user = await db.getUserByEmail(email);
    if (!user) {
      return c.json({ error: 'invalid email or password' }, 401);
    }

    const valid = await verifyPassword(password, user.password);
    if (!valid) {
      return c.json({ error: 'invalid email or password' }, 401);
    }

    const token = await generateToken({ id: user.id, email: user.email, name: user.name, role: user.role }, c.env);

    return c.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
    });
  } catch (e: any) {
    return c.json({ error: e?.message || 'login failed' }, 500);
  }
});

// ── Get current user ──
app.get('/api/auth/me', async (c) => {
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'unauthorized' }, 401);
  }
  const user = await verifyToken(auth.slice(7), c.env);
  if (!user) {
    return c.json({ error: 'invalid or expired token' }, 401);
  }
  return c.json({ user });
});

// ── Register (uses challenge key for anti-DOS, role from button) ──
app.post('/api/auth/register', async (c) => {
  try {
    const { email, password, name, role, challenge } = await c.req.json();
    if (!email || !password || !role || !challenge) {
      return c.json({ error: 'email, password, role, and challenge key are required' }, 400);
    }
    if (!['executive', 'admin'].includes(role)) {
      return c.json({ error: 'role must be "executive" or "admin"' }, 400);
    }
    if (password.length < 8) {
      return c.json({ error: 'password must be at least 8 characters' }, 400);
    }

    const chalOk = await verifyChallenge(challenge, c.env.JWT_SECRET);
    if (!chalOk) {
      return c.json({ error: 'invalid or expired challenge key — refresh the page' }, 400);
    }

    const db = new DB(c.env);
    const existingUser = await db.getUserByEmail(email);
    if (existingUser) {
      return c.json({ error: 'email already registered' }, 409);
    }

    const passwordHash = await hashPassword(password);
    const user = await db.createUser(email, passwordHash, name || '', role);
    const token = await generateToken({ id: user.id, email: user.email, name: user.name, role: user.role }, c.env);

    return c.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } }, 201);
  } catch (e: any) {
    return c.json({ error: e?.message || 'registration failed' }, 500);
  }
});

// ── Generate one-time registration keys (admin only) ──
app.post('/api/auth/admin/keys', async (c) => {
  try {
    const auth = c.req.header('Authorization');
    if (!auth?.startsWith('Bearer ')) {
      return c.json({ error: 'unauthorized' }, 401);
    }
    const currentUser = await verifyToken(auth.slice(7), c.env);
    if (!currentUser) {
      return c.json({ error: 'invalid or expired token' }, 401);
    }
    if (currentUser.role !== 'admin') {
      return c.json({ error: 'admin access required' }, 403);
    }

    const { count = 10, role = 'executive', daysValid = 30 } = await c.req.json();
    if (!['executive', 'admin'].includes(role)) {
      return c.json({ error: 'role must be "executive" or "admin"' }, 400);
    }

    const db = new DB(c.env);
    const expiresAt = new Date(Date.now() + daysValid * 86400000).toISOString();
    const keys: string[] = [];

    for (let i = 0; i < Math.min(count, 100); i++) {
      const code = generateKeyCode();
      await db.insertKey(code, role, currentUser.id, expiresAt);
      keys.push(code);
    }

    return c.json({ keys, count: keys.length, role, expiresAt });
  } catch (e: any) {
    return c.json({ error: e?.message || 'key generation failed' }, 500);
  }
});

// ── Key stats (admin only) ──
app.get('/api/auth/admin/keys/stats', async (c) => {
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'unauthorized' }, 401);
  }
  const currentUser = await verifyToken(auth.slice(7), c.env);
  if (!currentUser || currentUser.role !== 'admin') {
    return c.json({ error: 'admin access required' }, 403);
  }
  const db = new DB(c.env);
  const stats = await db.getKeysStats();
  return c.json({ stats });
});

export default app;
