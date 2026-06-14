export interface User {
  id: number;
  email: string;
  password: string;
  name: string;
  role: 'executive' | 'admin';
  created_at: string;
}

export interface RegistrationKey {
  id: number;
  key: string;
  role: 'executive' | 'admin';
  used: number;
  used_by: number | null;
  used_at: string | null;
  created_by: number;
  created_at: string;
  expires_at: string;
}

export interface Env {
  DB: D1Database;
  JWT_SECRET: string;
}

export type UserWithoutPassword = Omit<User, 'password'>;
