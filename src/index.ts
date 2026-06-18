import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { DB } from './db';
import { hashPassword, verifyPassword, generateToken, generateSessionToken, verifyToken, generateKeyCode, generateChallenge, signChallenge, verifyChallenge } from './crypto';

const app = new Hono<{ Bindings: Env; Variables: { user: any } }>();

app.use('/*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'], allowHeaders: ['Content-Type', 'Authorization'] }));

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

// ── Helpers ──

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateId(): string {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function nowISO(): string {
  return new Date().toISOString();
}

async function getUser(c: any) {
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) return null;
  const payload = await verifyToken(auth.slice(7), c.env);
  if (!payload) return null;
  const team = payload.role === 'business' ? 'business' : 'sales';
  return {
    id: String(payload.id),
    organizationId: 'org_demo',
    organizationName: 'DealMaker Demo',
    email: payload.email,
    name: payload.name || '',
    team,
    canApproveHighRisk: team === 'business',
  };
}

function versionedUpdate(id: string, expectedVersion: number, updater: (deal: any) => any): any | null | 'version_mismatch' {
  const deal = dealStore.get(id);
  if (!deal) return null;
  if (deal.version !== expectedVersion) return 'version_mismatch';
  const updated = updater(deal);
  updated.version = deal.version + 1;
  updated.updatedAt = nowISO();
  dealStore.set(id, updated);
  return updated;
}

// ── In-memory deal store ──

const dealStore = new Map<string, any>();

// ── Deal endpoints ──

app.get('/api/deals', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const userDeals = Array.from(dealStore.values())
    .filter(d => d.organizationId === user.organizationId)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return c.json({ deals: userDeals });
});

app.post('/api/deals', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const body = await c.req.json();
  const id = generateId();
  const deal = {
    id,
    organizationId: user.organizationId,
    createdBy: user.id,
    assignedTo: undefined as string | undefined,
    version: 1,
    status: 'draft',
    rawConversation: body.rawConversation || '',
    extracted: body.extracted || {},
    chatHistory: body.chatHistory || [],
    email: body.email || null,
    validationIssues: body.validationIssues || [],
    validationMode: body.validationMode || 'rules_only',
    validationFailure: body.validationFailure || undefined,
    riskScore: undefined,
    complianceNotes: undefined,
    rejectReason: undefined,
    contractContent: undefined,
    contractStatus: undefined,
    contractHash: undefined,
    evaluation: undefined,
    bandRoomId: body.bandRoomId || undefined,
    archivedAt: undefined,
    createdAt: nowISO(),
    updatedAt: nowISO(),
  };
  dealStore.set(id, deal);
  return c.json({ deal }, 201);
});

app.get('/api/deals/:id', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const deal = dealStore.get(c.req.param('id'));
  if (!deal) return c.json({ error: 'deal not found' }, 404);
  return c.json({ deal });
});

app.post('/api/deals/:id/evaluate', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const deal = dealStore.get(c.req.param('id'));
  if (!deal) return c.json({ error: 'deal not found' }, 404);

  const score1 = randomInt(20, 95);
  const score2 = randomInt(30, 100);
  const score3 = randomInt(10, 90);
  const avg = (score1 + score2 + score3) / 3;
  const riskScore: 'low' | 'medium' | 'high' = avg >= 70 ? 'low' : avg >= 40 ? 'medium' : 'high';

  const evaluation = {
    id: generateId(),
    dealId: deal.id,
    proposalVersion: deal.version,
    riskScore,
    profitScore: score1,
    complianceScore: score2,
    priorityScore: score3,
    complianceNotes: [] as string[],
    recommendation: (riskScore === 'high' ? 'reject' : 'approve') as 'approve' | 'reject',
    reason: riskScore === 'high'
      ? 'High risk assessment — manual review recommended'
      : 'Passes automated checks',
    mode: 'rules_only' as const,
    provider: 'DealMaker Rules Engine',
    policySources: [] as string[],
    failureReason: undefined as string | undefined,
    contractDocument: undefined as string | undefined,
    createdBy: 'system',
    createdAt: nowISO(),
  };

  deal.evaluation = evaluation;
  deal.updatedAt = nowISO();
  dealStore.set(deal.id, deal);

  return c.json({ evaluation });
});

app.patch('/api/deals/:id/email', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { email, expectedVersion } = await c.req.json();
  const result = versionedUpdate(c.req.param('id'), expectedVersion, (deal) => {
    deal.email = email;
    return deal;
  });
  if (result === null) return c.json({ error: 'deal not found' }, 404);
  if (result === 'version_mismatch') return c.json({ error: 'version mismatch' }, 409);
  return c.json({ deal: result });
});

app.post('/api/deals/:id/submit', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { expectedVersion } = await c.req.json();
  const result = versionedUpdate(c.req.param('id'), expectedVersion, (deal) => {
    deal.status = 'pending_business_review';
    return deal;
  });
  if (result === null) return c.json({ error: 'deal not found' }, 404);
  if (result === 'version_mismatch') return c.json({ error: 'version mismatch' }, 409);
  return c.json({ deal: result });
});

app.post('/api/deals/:id/withdraw', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { expectedVersion } = await c.req.json();
  const result = versionedUpdate(c.req.param('id'), expectedVersion, (deal) => {
    deal.status = 'draft';
    return deal;
  });
  if (result === null) return c.json({ error: 'deal not found' }, 404);
  if (result === 'version_mismatch') return c.json({ error: 'version mismatch' }, 409);
  return c.json({ deal: result });
});

app.post('/api/deals/:id/approve', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { expectedVersion } = await c.req.json();
  const result = versionedUpdate(c.req.param('id'), expectedVersion, (deal) => {
    deal.status = 'approved';
    return deal;
  });
  if (result === null) return c.json({ error: 'deal not found' }, 404);
  if (result === 'version_mismatch') return c.json({ error: 'version mismatch' }, 409);
  return c.json({ deal: result });
});

app.post('/api/deals/:id/reject', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { expectedVersion, category, details } = await c.req.json();
  const result = versionedUpdate(c.req.param('id'), expectedVersion, (deal) => {
    deal.status = 'rejected';
    deal.rejectReason = `${category}: ${details}`;
    return deal;
  });
  if (result === null) return c.json({ error: 'deal not found' }, 404);
  if (result === 'version_mismatch') return c.json({ error: 'version mismatch' }, 409);
  return c.json({ deal: result });
});

app.post('/api/deals/:id/archive', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { expectedVersion } = await c.req.json();
  const result = versionedUpdate(c.req.param('id'), expectedVersion, (deal) => {
    deal.archivedAt = nowISO();
    return deal;
  });
  if (result === null) return c.json({ error: 'deal not found' }, 404);
  if (result === 'version_mismatch') return c.json({ error: 'version mismatch' }, 409);
  return c.json({ success: true });
});

app.post('/api/deals/:id/sign', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { expectedVersion, typedName } = await c.req.json();
  const result = versionedUpdate(c.req.param('id'), expectedVersion, (deal) => {
    deal.contractStatus = 'signed';
    deal.contractContent = `Signed by ${typedName} on ${nowISO()}`;
    deal.contractHash = generateId();
    return deal;
  });
  if (result === null) return c.json({ error: 'deal not found' }, 404);
  if (result === 'version_mismatch') return c.json({ error: 'version mismatch' }, 409);
  return c.json({ deal: result });
});

app.delete('/api/deals', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  dealStore.clear();
  return c.json({ success: true });
});

app.get('/api/deals/:id/events', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const deal = dealStore.get(c.req.param('id'));
  if (!deal) return c.json({ error: 'deal not found' }, 404);
  return c.json({ events: [], transcript: [] });
});

// ── Agent endpoints ──

app.post('/api/agents/analyze', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { rawText } = await c.req.json();
  const extracted: Record<string, any> = {};
  const missingFields: string[] = [];

  if (rawText) {
    const nameMatch = rawText.match(/(?:client|company|organization)\s*(?:name|is|:)?\s*["']?([A-Za-z0-9\s&]+?)["']?(?:\s*\.|\s*,|\s*$)/i);
    if (nameMatch) extracted.clientName = nameMatch[1].trim();

    const valueMatch = rawText.match(/\$?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)\s*(?:k|K|thousand|million|M|billion|B)?/);
    if (valueMatch) {
      let val = parseFloat(valueMatch[1].replace(/,/g, ''));
      if (rawText.toLowerCase().includes('million') || /m\b/i.test(rawText)) val *= 1000000;
      else if (rawText.toLowerCase().includes('billion') || /b\b/i.test(rawText)) val *= 1000000000;
      else if (rawText.toLowerCase().includes('k') || rawText.toLowerCase().includes('thousand')) val *= 1000;
      extracted.value = val;
    }

    if (/descri|service|product|project|solution|offering/i.test(rawText)) {
      const descMatch = rawText.match(/(?:regarding|about|for|:)\s*["']?([A-Za-z0-9\s]+?)["']?(?:\s*\.|\s*,|\s*$)/i);
      if (descMatch) extracted.description = descMatch[1].trim();
      else extracted.description = rawText.length > 120 ? rawText.slice(0, 120) + '...' : rawText;
    }

    if (/decision|manager|director|head|lead|president|CEO|CFO|CTO/i.test(rawText)) {
      const dmMatch = rawText.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/);
      if (dmMatch) extracted.decisionMaker = dmMatch[1].trim();
    }

    const emailMatch = rawText.match(/\b[\w.+-]+@[\w.-]+\.\w{2,}\b/);
    if (emailMatch) extracted.contactEmail = emailMatch[0];
  }

  if (!extracted.clientName) missingFields.push('clientName');
  if (!extracted.value) missingFields.push('value');
  if (!extracted.description) missingFields.push('description');
  if (!extracted.decisionMaker) missingFields.push('decisionMaker');
  if (!extracted.contactEmail) missingFields.push('contactEmail');

  return c.json({
    extracted,
    missingFields,
    nextQuestion: missingFields.length > 0 ? `Please provide: ${missingFields.join(', ')}` : undefined,
  });
});

app.post('/api/agents/generate-email', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { info } = await c.req.json();
  const clientName = info?.clientName || 'Valued Client';
  const email = {
    to: info?.contactEmail || 'client@example.com',
    subject: `Proposal for ${clientName}`,
    body: `Dear ${clientName},\n\nThank you for your interest. Please find attached our proposal for your review.\n\nProposal Details:\n${info?.description || 'As discussed'}\n\nValue: ${info?.value ? `$${info.value.toLocaleString()}` : 'To be determined'}\n\nBest regards,\n${user.name}`,
  };
  return c.json({
    email,
    validationIssues: [],
    validationMode: 'rules_only',
    validationFailure: undefined,
    roomId: undefined,
  });
});

app.post('/api/agents/missing-info', async (c) => {
  const user = await getUser(c);
  if (!user) return c.json({ error: 'unauthorized' }, 401);
  const { current, field, answer } = await c.req.json();
  const extracted = { ...(current || {}), [field]: answer };
  const missingFields = ['clientName', 'value', 'description', 'decisionMaker', 'contactEmail']
    .filter(f => !extracted[f]);
  return c.json({
    extracted,
    missingFields,
    nextQuestion: missingFields.length > 0 ? `Still needed: ${missingFields.join(', ')}` : undefined,
  });
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
