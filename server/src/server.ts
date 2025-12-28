import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from 'jsonwebtoken';
import { config } from './config.js';
import { InMemoryOtpStore } from './otpStore.js';
import { PgOtpStore } from './pgOtpStore.js';
import { requestOtpSchema, verifyOtpSchema, addAddressSchema, transferSchema } from './schema.js';
import { makeTwilioClient, sendOtpSms } from './twilioClient.js';
import { getPool, runMigrations } from './db.js';
import { requireAuth } from './auth.js';

let otpStore: InMemoryOtpStore | PgOtpStore;
const useDb = !!process.env.DATABASE_URL;
if (useDb) {
  const pool = getPool();
  otpStore = new PgOtpStore(pool);
  runMigrations().catch((err) => {
    console.error('Migration failed', err);
    process.exit(1);
  });
} else {
  otpStore = new InMemoryOtpStore();
}

const twilioClient = config.twilio.accountSid ? makeTwilioClient() : null;

const fastify = Fastify({ logger: true });
fastify.register(cors, { origin: true });

fastify.post('/auth/request-otp', async (request, reply) => {
  const parsed = requestOtpSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const { phone } = parsed.data;
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  await Promise.resolve(otpStore.issue(phone, code, config.otp.ttlMs));

  if (!twilioClient) {
    request.log.warn('Twilio not configured; logging OTP instead');
    request.log.info({ phone, code }, 'Dev OTP');
  } else {
    try {
      await sendOtpSms(twilioClient, phone, code);
    } catch (err) {
      request.log.error({ err }, 'Failed to send OTP');
      return reply.code(502).send({ error: 'Failed to send OTP' });
    }
  }

  return reply.send({ ok: true });
});

fastify.post('/auth/verify-otp', async (request, reply) => {
  const parsed = verifyOtpSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const { phone, code } = parsed.data;
  const ok = await Promise.resolve(otpStore.verify(phone, code, config.otp.maxAttempts));
  if (!ok) {
    return reply.code(401).send({ error: 'Invalid or expired code' });
  }
  let userId: number | null = null;
  if (useDb) {
    const pool = getPool();
    const res = await pool.query('INSERT INTO users (phone_e164) VALUES ($1) ON CONFLICT (phone_e164) DO UPDATE SET phone_e164 = EXCLUDED.phone_e164 RETURNING id', [phone]);
    userId = res.rows[0]?.id ?? null;
  }
  const token = jwt.sign({ sub: phone, uid: userId ?? undefined }, config.jwtSecret, { expiresIn: '30d' });
  return reply.send({ ok: true, phone, token });
});

fastify.get('/me', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  return reply.send({ ok: true, phone: ctx.phone, uid: ctx.uid });
});

fastify.post('/addresses', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = addAddressSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.format() });
  const { address, isDefault } = parsed.data;
  const pool = getPool();
  const userRes = await pool.query('SELECT id FROM users WHERE phone_e164 = $1', [ctx.phone]);
  const uid = ctx.uid ?? userRes.rows[0]?.id;
  if (!uid) return reply.code(400).send({ error: 'User not found' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (isDefault) {
      await client.query('UPDATE addresses SET is_default = FALSE WHERE user_id = $1', [uid]);
    }
    await client.query(
      `INSERT INTO addresses (user_id, address, is_default) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, address) DO UPDATE SET is_default = EXCLUDED.is_default`,
      [uid, address, isDefault ?? false]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    request.log.error({ err }, 'Failed to save address');
    return reply.code(500).send({ error: 'Failed to save address' });
  } finally {
    client.release();
  }
  return reply.send({ ok: true });
});

fastify.get('/addresses', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const pool = getPool();
  const res = await pool.query('SELECT address, is_default FROM addresses WHERE user_id = (SELECT id FROM users WHERE phone_e164 = $1)', [ctx.phone]);
  return reply.send({ ok: true, addresses: res.rows });
});

fastify.post('/transfers', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = transferSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.format() });
  const { to_phone, amount_lamports } = parsed.data;
  const pool = getPool();

  // Resolve sender and receiver
  const senderRes = await pool.query('SELECT id FROM users WHERE phone_e164 = $1', [ctx.phone]);
  const senderId = senderRes.rows[0]?.id ?? null;
  const receiverRes = await pool.query('SELECT id FROM users WHERE phone_e164 = $1', [to_phone]);
  const receiverId = receiverRes.rows[0]?.id ?? null;
  let toAddress: string | null = null;
  if (receiverId) {
    const addrRes = await pool.query('SELECT address FROM addresses WHERE user_id = $1 AND is_default = TRUE LIMIT 1', [receiverId]);
    toAddress = addrRes.rows[0]?.address ?? null;
  }

  // Stub transfer record; no on-chain send yet
  const insert = await pool.query(
    `INSERT INTO transfers (from_user, to_user, to_phone, to_address, amount_lamports, status)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [senderId, receiverId, to_phone, toAddress, BigInt(amount_lamports as any), 'pending']
  );

  return reply.send({ ok: true, transfer_id: insert.rows[0].id, to_address: toAddress, status: 'pending' });
});

const start = async () => {
  try {
    await fastify.listen({ port: config.port, host: '0.0.0.0' });
    fastify.log.info(`API listening on ${config.port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
