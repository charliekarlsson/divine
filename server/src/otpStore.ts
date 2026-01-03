import { nanoid } from 'nanoid';

export type OtpRecord = {
  code: string;
  expiresAt: number;
  attempts: number;
};

export interface OtpStore {
  issue(identifier: string, code: string, ttlMs: number): Promise<string> | string;
  verify(identifier: string, code: string, maxAttempts: number): Promise<boolean> | boolean;
}

// Simple in-memory store for development. Swap to Redis in production.
export class InMemoryOtpStore implements OtpStore {
  private store = new Map<string, OtpRecord>();

  issue(identifier: string, code: string, ttlMs: number): string {
    const id = nanoid();
    this.store.set(identifier, {
      code,
      expiresAt: Date.now() + ttlMs,
      attempts: 0
    });
    return id;
  }

  verify(identifier: string, code: string, maxAttempts: number): boolean {
    const rec = this.store.get(identifier);
    if (!rec) return false;
    if (Date.now() > rec.expiresAt) {
      this.store.delete(identifier);
      return false;
    }
    if (rec.attempts >= maxAttempts) {
      this.store.delete(identifier);
      return false;
    }
    rec.attempts += 1;
    if (rec.code === code) {
      this.store.delete(identifier);
      return true;
    }
    this.store.set(identifier, rec);
    return false;
  }
}
