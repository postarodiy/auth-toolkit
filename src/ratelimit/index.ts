interface RateLimitEntry {
  count: number;
  resetTime: number;
  failedAttempts: number;
  lastFailedAttempt?: number;
}

export type RateLimitEvent =
  | { type: 'blocked_attempt'; identifier: string; expiresInSeconds: number }
  | { type: 'limit_exceeded'; identifier: string; count: number; limit: number }
  | { type: 'ip_blocked'; identifier: string; failedAttempts: number; blockDurationSeconds: number }
  | { type: 'cleanup'; activeEntries: number; blockedIPs: number };

export interface RateLimiterConfig {
  windowMs: number;
  maxRequests: number;
  maxFailedAttempts?: number;
  blockDurationMs?: number;
  cleanupIntervalMs?: number;
  onEvent?: (event: RateLimitEvent) => void;
}

const DEFAULT_MAX_FAILED_ATTEMPTS = 5;
const DEFAULT_BLOCK_DURATION_MS = 15 * 60 * 1000;
const DEFAULT_CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

export class RateLimiter {
  private requestMap = new Map<string, RateLimitEntry>();
  private blockedIPs = new Map<string, number>();
  private config: Required<Omit<RateLimiterConfig, 'onEvent'>> & Pick<RateLimiterConfig, 'onEvent'>;
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(config: RateLimiterConfig) {
    this.config = {
      maxFailedAttempts: DEFAULT_MAX_FAILED_ATTEMPTS,
      blockDurationMs: DEFAULT_BLOCK_DURATION_MS,
      cleanupIntervalMs: DEFAULT_CLEANUP_INTERVAL_MS,
      ...config,
    };

    this.cleanupInterval = setInterval(() => this.cleanup(), this.config.cleanupIntervalMs);
    if (typeof this.cleanupInterval.unref === 'function') {
      this.cleanupInterval.unref();
    }
  }

  isAllowed(identifier: string): boolean {
    const blockExpiry = this.blockedIPs.get(identifier);
    if (blockExpiry && blockExpiry > Date.now()) {
      this.config.onEvent?.({
        type: 'blocked_attempt',
        identifier,
        expiresInSeconds: Math.round((blockExpiry - Date.now()) / 1000),
      });
      return false;
    }
    if (blockExpiry && blockExpiry <= Date.now()) {
      this.blockedIPs.delete(identifier);
    }

    const now = Date.now();
    const entry = this.requestMap.get(identifier);

    if (!entry || entry.resetTime <= now) {
      this.requestMap.set(identifier, { count: 1, resetTime: now + this.config.windowMs, failedAttempts: 0 });
      return true;
    }

    entry.count++;

    if (entry.count > this.config.maxRequests) {
      this.config.onEvent?.({
        type: 'limit_exceeded',
        identifier,
        count: entry.count,
        limit: this.config.maxRequests,
      });
      return false;
    }

    return true;
  }

  recordFailedAttempt(identifier: string): void {
    const now = Date.now();
    const entry = this.requestMap.get(identifier) ?? { count: 0, resetTime: now + this.config.windowMs, failedAttempts: 0 };

    entry.failedAttempts++;
    entry.lastFailedAttempt = now;
    this.requestMap.set(identifier, entry);

    if (entry.failedAttempts >= this.config.maxFailedAttempts) {
      const blockUntil = now + this.config.blockDurationMs;
      this.blockedIPs.set(identifier, blockUntil);
      this.config.onEvent?.({
        type: 'ip_blocked',
        identifier,
        failedAttempts: entry.failedAttempts,
        blockDurationSeconds: Math.round(this.config.blockDurationMs / 1000),
      });
    }
  }

  resetFailedAttempts(identifier: string): void {
    const entry = this.requestMap.get(identifier);
    if (entry) {
      entry.failedAttempts = 0;
      entry.lastFailedAttempt = undefined;
    }
  }

  getRemainingRequests(identifier: string): number {
    const entry = this.requestMap.get(identifier);
    if (!entry || entry.resetTime <= Date.now()) {
      return this.config.maxRequests;
    }
    return Math.max(0, this.config.maxRequests - entry.count);
  }

  getStats(): { activeEntries: number; blockedIPs: number } {
    return { activeEntries: this.requestMap.size, blockedIPs: this.blockedIPs.size };
  }

  /** Stops the background cleanup interval. Call in tests or on graceful shutdown. */
  destroy(): void {
    clearInterval(this.cleanupInterval);
  }

  private cleanup(): void {
    const now = Date.now();

    for (const [identifier, entry] of this.requestMap.entries()) {
      if (entry.resetTime <= now) {
        this.requestMap.delete(identifier);
      }
    }
    for (const [identifier, blockExpiry] of this.blockedIPs.entries()) {
      if (blockExpiry <= now) {
        this.blockedIPs.delete(identifier);
      }
    }

    this.config.onEvent?.({
      type: 'cleanup',
      activeEntries: this.requestMap.size,
      blockedIPs: this.blockedIPs.size,
    });
  }
}
