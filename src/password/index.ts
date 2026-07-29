import bcrypt from 'bcryptjs';

export interface HashPasswordOptions {
  costFactor?: number;
}

export async function hashPassword(plainText: string, options?: HashPasswordOptions): Promise<string> {
  return bcrypt.hash(plainText, options?.costFactor ?? 10);
}

export async function verifyPassword(plainText: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plainText, hash);
}
