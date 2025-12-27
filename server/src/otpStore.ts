import { nanoid } from 'nanoid';

export type OtpRecord = {
  code: string;
  expiresAt: number;
  attempts: number;
};

export interface OtpStore {
  issue(phoneE164: string, code: string, ttlMs: number): string;
  verify(phoneE164: string, code: string, maxAttempts: number): boolean;
}

// Simple in-memory store for development. Swap to Redis in production.
export class InMemoryOtpStore implements OtpStore {
  private store = new Map<string, OtpRecord>();

  issue(phoneE164: string, code: string, ttlMs: number): string {
    const id = nanoid();
    this.store.set(phoneE164, {
      code,
      expiresAt: Date.now() + ttlMs,
      attempts: 0
    });
    return id;
  }

  verify(phoneE164: string, code: string, maxAttempts: number): boolean {
    const rec = this.store.get(phoneE164);
    if (!rec) return false;
    if (Date.now() > rec.expiresAt) {
      this.store.delete(phoneE164);
      return false;
    }
    if (rec.attempts >= maxAttempts) {
      this.store.delete(phoneE164);
      return false;
    }
    rec.attempts += 1;
    if (rec.code === code) {
      this.store.delete(phoneE164);
      return true;
    }
    this.store.set(phoneE164, rec);
    return false;
  }
}
