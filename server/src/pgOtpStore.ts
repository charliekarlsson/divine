import { Pool } from 'pg';
import { OtpStore } from './otpStore.js';

export class PgOtpStore implements OtpStore {
  constructor(private pool: Pool) {}

  async issue(identifier: string, code: string, ttlMs: number): Promise<string> {
    const expiresAt = new Date(Date.now() + ttlMs);
    await this.pool.query(
      `INSERT INTO otps (phone_e164, code, expires_at, attempts)
       VALUES ($1, $2, $3, 0)
       ON CONFLICT (phone_e164)
       DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at, attempts = 0` ,
      [identifier, code, expiresAt]
    );
    return identifier;
  }

  async verify(identifier: string, code: string, maxAttempts: number): Promise<boolean> {
    const res = await this.pool.query(
      'SELECT code, expires_at, attempts FROM otps WHERE phone_e164 = $1',
      [identifier]
    );
    if (res.rowCount === 0) return false;
    const row = res.rows[0];
    if (row.attempts >= maxAttempts) {
      await this.pool.query('DELETE FROM otps WHERE phone_e164 = $1', [identifier]);
      return false;
    }
    if (new Date(row.expires_at).getTime() < Date.now()) {
      await this.pool.query('DELETE FROM otps WHERE phone_e164 = $1', [identifier]);
      return false;
    }
    const nextAttempts = row.attempts + 1;
    if (row.code === code) {
      await this.pool.query('DELETE FROM otps WHERE phone_e164 = $1', [identifier]);
      return true;
    }
    await this.pool.query('UPDATE otps SET attempts = $2 WHERE phone_e164 = $1', [identifier, nextAttempts]);
    return false;
  }
}
