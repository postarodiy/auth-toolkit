import { describe, test, expect } from 'vitest';
import { hashPassword, verifyPassword } from './index';

describe('hashPassword / verifyPassword', () => {
  test('produces a bcrypt-formatted hash', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).toMatch(/^\$2[aby]\$\d{2}\$/);
  });

  test('salts each hash uniquely, even for the same input', async () => {
    const [a, b] = await Promise.all([hashPassword('same-password'), hashPassword('same-password')]);
    expect(a).not.toBe(b);
  });

  test('verifies a correct password', async () => {
    const hash = await hashPassword('my-password');
    expect(await verifyPassword('my-password', hash)).toBe(true);
  });

  test('rejects an incorrect password', async () => {
    const hash = await hashPassword('my-password');
    expect(await verifyPassword('wrong-password', hash)).toBe(false);
  });

  test('respects a custom cost factor', async () => {
    const hash = await hashPassword('my-password', { costFactor: 12 });
    const [, , costSegment] = hash.split('$');
    expect(costSegment).toBe('12');
  });

  test('defaults to cost factor 10', async () => {
    const hash = await hashPassword('my-password');
    const [, , costSegment] = hash.split('$');
    expect(costSegment).toBe('10');
  });
});
