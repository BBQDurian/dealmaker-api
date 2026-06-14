import type { Env, User, RegistrationKey } from './types';

export class DB {
  db: D1Database;

  constructor(env: Env) {
    this.db = env.DB;
  }

  async createUser(email: string, password: string, name: string, role: 'executive' | 'admin'): Promise<User> {
    const result = await this.db
      .prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?) RETURNING *')
      .bind(email, password, name, role)
      .first<User>();
    return result!;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    return (await this.db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<User>()) || null;
  }

  async getUserById(id: number): Promise<User | null> {
    return (await this.db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first<User>()) || null;
  }

  async getKey(key: string): Promise<RegistrationKey | null> {
    return (await this.db.prepare('SELECT * FROM registration_keys WHERE key = ?').bind(key).first<RegistrationKey>()) || null;
  }

  async consumeKey(key: string, userId: number): Promise<boolean> {
    const result = await this.db
      .prepare("UPDATE registration_keys SET used = 1, used_by = ?, used_at = datetime('now') WHERE key = ? AND used = 0 AND expires_at > datetime('now')")
      .bind(userId, key)
      .run();
    return result.changes > 0;
  }

  async insertKey(key: string, role: 'executive' | 'admin', createdBy: number, expiresAt: string): Promise<RegistrationKey> {
    const result = await this.db
      .prepare('INSERT INTO registration_keys (key, role, created_by, expires_at) VALUES (?, ?, ?, ?) RETURNING *')
      .bind(key, role, createdBy, expiresAt)
      .first<RegistrationKey>();
    return result!;
  }

  async getKeysStats(): Promise<{ total: number; used: number; available: number }> {
    const total = await this.db.prepare('SELECT COUNT(*) as count FROM registration_keys').first<{ count: number }>();
    const used = await this.db.prepare('SELECT COUNT(*) as count FROM registration_keys WHERE used = 1').first<{ count: number }>();
    const available = await this.db.prepare("SELECT COUNT(*) as count FROM registration_keys WHERE used = 0 AND expires_at > datetime('now')").first<{ count: number }>();
    return {
      total: total?.count ?? 0,
      used: used?.count ?? 0,
      available: available?.count ?? 0,
    };
  }

}
