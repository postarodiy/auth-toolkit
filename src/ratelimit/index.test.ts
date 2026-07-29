import { describe, test, expect, vi, afterEach } from 'vitest';
import { RateLimiter, type RateLimitEvent } from './index';

afterEach(() => {
  vi.useRealTimers();
});

describe('RateLimiter.isAllowed', () => {
  test('allows requests up to the limit, then denies', () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 3 });
    try {
      expect(limiter.isAllowed('ip1')).toBe(true);
      expect(limiter.isAllowed('ip1')).toBe(true);
      expect(limiter.isAllowed('ip1')).toBe(true);
      expect(limiter.isAllowed('ip1')).toBe(false);
    } finally {
      limiter.destroy();
    }
  });

  test('tracks identifiers independently', () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 1 });
    try {
      expect(limiter.isAllowed('ip1')).toBe(true);
      expect(limiter.isAllowed('ip2')).toBe(true);
      expect(limiter.isAllowed('ip1')).toBe(false);
    } finally {
      limiter.destroy();
    }
  });

  test('resets the window after windowMs elapses', () => {
    vi.useFakeTimers();
    const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 1 });
    try {
      expect(limiter.isAllowed('ip1')).toBe(true);
      expect(limiter.isAllowed('ip1')).toBe(false);

      vi.advanceTimersByTime(1001);
      expect(limiter.isAllowed('ip1')).toBe(true);
    } finally {
      limiter.destroy();
    }
  });

  test('emits limit_exceeded when the window cap is passed', () => {
    const events: RateLimitEvent[] = [];
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 1, onEvent: (e) => events.push(e) });
    try {
      limiter.isAllowed('ip1');
      limiter.isAllowed('ip1');
      expect(events).toContainEqual(expect.objectContaining({ type: 'limit_exceeded', identifier: 'ip1' }));
    } finally {
      limiter.destroy();
    }
  });
});

describe('RateLimiter failed-attempt blocking', () => {
  test('blocks an identifier after maxFailedAttempts and emits ip_blocked', () => {
    const events: RateLimitEvent[] = [];
    const limiter = new RateLimiter({
      windowMs: 60_000,
      maxRequests: 100,
      maxFailedAttempts: 3,
      blockDurationMs: 30_000,
      onEvent: (e) => events.push(e),
    });
    try {
      limiter.recordFailedAttempt('ip1');
      limiter.recordFailedAttempt('ip1');
      expect(limiter.isAllowed('ip1')).toBe(true);

      limiter.recordFailedAttempt('ip1');
      expect(events).toContainEqual(
        expect.objectContaining({ type: 'ip_blocked', identifier: 'ip1', failedAttempts: 3 })
      );
      expect(limiter.isAllowed('ip1')).toBe(false);
    } finally {
      limiter.destroy();
    }
  });

  test('emits blocked_attempt while a block is active', () => {
    const events: RateLimitEvent[] = [];
    const limiter = new RateLimiter({
      windowMs: 60_000,
      maxRequests: 100,
      maxFailedAttempts: 1,
      onEvent: (e) => events.push(e),
    });
    try {
      limiter.recordFailedAttempt('ip1');
      limiter.isAllowed('ip1');
      expect(events).toContainEqual(expect.objectContaining({ type: 'blocked_attempt', identifier: 'ip1' }));
    } finally {
      limiter.destroy();
    }
  });

  test('unblocks automatically once blockDurationMs elapses', () => {
    vi.useFakeTimers();
    const limiter = new RateLimiter({
      windowMs: 60_000,
      maxRequests: 100,
      maxFailedAttempts: 1,
      blockDurationMs: 1000,
    });
    try {
      limiter.recordFailedAttempt('ip1');
      expect(limiter.isAllowed('ip1')).toBe(false);

      vi.advanceTimersByTime(1001);
      expect(limiter.isAllowed('ip1')).toBe(true);
    } finally {
      limiter.destroy();
    }
  });

  test('resetFailedAttempts clears the counter without unblocking an active block', () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 100, maxFailedAttempts: 5 });
    try {
      limiter.recordFailedAttempt('ip1');
      limiter.recordFailedAttempt('ip1');
      limiter.resetFailedAttempts('ip1');
      limiter.recordFailedAttempt('ip1');
      limiter.recordFailedAttempt('ip1');
      // Only 2 failed attempts since the reset - below the default-5 threshold.
      expect(limiter.isAllowed('ip1')).toBe(true);
    } finally {
      limiter.destroy();
    }
  });
});

describe('RateLimiter.getRemainingRequests', () => {
  test('reports remaining capacity within the window', () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 5 });
    try {
      limiter.isAllowed('ip1');
      limiter.isAllowed('ip1');
      expect(limiter.getRemainingRequests('ip1')).toBe(3);
    } finally {
      limiter.destroy();
    }
  });

  test('reports full capacity for an unseen identifier', () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 5 });
    try {
      expect(limiter.getRemainingRequests('never-seen')).toBe(5);
    } finally {
      limiter.destroy();
    }
  });
});

describe('RateLimiter cleanup and lifecycle', () => {
  test('cleanup evicts expired entries and emits a cleanup event', () => {
    vi.useFakeTimers();
    const events: RateLimitEvent[] = [];
    const limiter = new RateLimiter({
      windowMs: 100,
      maxRequests: 5,
      cleanupIntervalMs: 1000,
      onEvent: (e) => events.push(e),
    });
    try {
      limiter.isAllowed('ip1');
      expect(limiter.getStats().activeEntries).toBe(1);

      vi.advanceTimersByTime(1001);
      expect(events).toContainEqual(expect.objectContaining({ type: 'cleanup' }));
      expect(limiter.getStats().activeEntries).toBe(0);
    } finally {
      limiter.destroy();
    }
  });

  test('destroy stops the background cleanup timer', () => {
    vi.useFakeTimers();
    const events: RateLimitEvent[] = [];
    const limiter = new RateLimiter({
      windowMs: 100,
      maxRequests: 5,
      cleanupIntervalMs: 1000,
      onEvent: (e) => events.push(e),
    });
    limiter.destroy();

    vi.advanceTimersByTime(5000);
    expect(events.filter((e) => e.type === 'cleanup')).toHaveLength(0);
  });
});
