import { Pool } from 'pg';
import { config } from './config.js';

let pool: Pool | null = null;

export function getPool(): Pool {
  if (pool) return pool;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is required for Postgres pool.');
  }
  // Railway and many managed Postgres providers require TLS; allow self-signed certs by default.
  const ssl = { rejectUnauthorized: process.env.DB_STRICT_SSL === 'true' ? true : false };
  pool = new Pool({ connectionString, ssl });
  return pool;
}

export async function runMigrations() {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        phone_e164 TEXT UNIQUE,
        email TEXT UNIQUE,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;');
    await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT UNIQUE;');
    await client.query('ALTER TABLE users ALTER COLUMN phone_e164 DROP NOT NULL;');
    await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT UNIQUE;');
    await client.query(`
      CREATE TABLE IF NOT EXISTS otps (
        phone_e164 TEXT PRIMARY KEY,
        code TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS addresses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        address TEXT NOT NULL,
        is_default BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, address)
      );
      CREATE INDEX IF NOT EXISTS idx_addresses_user_default ON addresses(user_id) WHERE is_default = TRUE;
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS transfers (
        id SERIAL PRIMARY KEY,
        from_user INTEGER REFERENCES users(id) ON DELETE SET NULL,
        to_user INTEGER REFERENCES users(id) ON DELETE SET NULL,
        from_address TEXT,
        to_phone TEXT NOT NULL,
        to_address TEXT,
        amount_lamports BIGINT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        tx_signature TEXT,
        memo TEXT,
        prepared_tx_base64 TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`ALTER TABLE transfers ADD COLUMN IF NOT EXISTS from_address TEXT;`);
    await client.query(`ALTER TABLE transfers ADD COLUMN IF NOT EXISTS memo TEXT;`);
    await client.query(`ALTER TABLE transfers ADD COLUMN IF NOT EXISTS prepared_tx_base64 TEXT;`);
    await client.query(`ALTER TABLE transfers ALTER COLUMN to_phone DROP NOT NULL;`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        phone_e164 TEXT,
        address TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, phone_e164)
      );
      CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id);
    `);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
