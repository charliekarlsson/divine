import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from 'jsonwebtoken';
import { randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { config } from './config.js';
import { InMemoryOtpStore } from './otpStore.js';
import { PgOtpStore } from './pgOtpStore.js';
import { requestOtpSchema, verifyOtpSchema, addAddressSchema, prepareTransferSchema, submitTransferSchema, passwordAuthSchema, usernamePasswordSchema, linkPhoneSchema, contactSchema } from './schema.js';
import { makeTwilioClient, sendOtpSms } from './twilioClient.js';
import { getPool, runMigrations } from './db.js';
import { requireAuth } from './auth.js';
import { buildUnsignedTransfer, relaySignedTransaction, serializeUnsignedTransaction } from './solana.js';
import { makePostmarkClient, sendOtpEmail } from './mailer.js';

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
const postmarkClient = config.postmark.serverToken ? makePostmarkClient() : null;

const hashPassword = (password: string) => {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `s:${salt}:${derived}`;
};

const verifyPassword = (password: string, stored: string | null) => {
  if (!stored || !stored.startsWith('s:')) return false;
  const parts = stored.split(':');
  if (parts.length !== 3) return false;
  const [, salt, hash] = parts;
  const derived = scryptSync(password, salt, 64).toString('hex');
  try {
    return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(derived, 'hex'));
  } catch {
    return false;
  }
};

const fastify = Fastify({ logger: true });
fastify.register(cors, {
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
  credentials: true
});

fastify.post('/auth/request-otp', async (request, reply) => {
  const parsed = requestOtpSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const { phone, email } = parsed.data;
  const channel = email ? 'email' : 'sms';
  const identifier = email ?? phone!;
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  await Promise.resolve(otpStore.issue(identifier, code, config.otp.ttlMs));

  if (channel === 'sms') {
    if (!twilioClient) {
      request.log.warn('Twilio not configured; logging OTP instead');
      request.log.info({ phone: identifier, code }, 'Dev OTP');
    } else {
      try {
        await sendOtpSms(twilioClient, identifier, code);
      } catch (err) {
        request.log.error({ err }, 'Failed to send OTP');
        return reply.code(502).send({ error: 'Failed to send OTP' });
      }
    }
  } else {
    if (!postmarkClient) {
      request.log.error('Postmark not configured; cannot send email OTP');
      return reply.code(500).send({ error: 'Email delivery not configured' });
    }
    try {
      await sendOtpEmail(postmarkClient, identifier, code);
    } catch (err) {
      request.log.error({ err }, 'Failed to send email OTP');
      return reply.code(502).send({ error: 'Failed to send OTP' });
    }
  }

  return reply.send({ ok: true, channel });
});

fastify.post('/auth/verify-otp', async (request, reply) => {
  const parsed = verifyOtpSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const { phone, email, code } = parsed.data;
  const identifier = email ?? phone!;
  const ok = await Promise.resolve(otpStore.verify(identifier, code, config.otp.maxAttempts));
  if (!ok) {
    return reply.code(401).send({ error: 'Invalid or expired code' });
  }
  let userId: number | null = null;
  if (useDb) {
    const pool = getPool();
    if (email) {
      const res = await pool.query('INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id', [email]);
      userId = res.rows[0]?.id ?? null;
    } else {
      const res = await pool.query('INSERT INTO users (phone_e164) VALUES ($1) ON CONFLICT (phone_e164) DO UPDATE SET phone_e164 = EXCLUDED.phone_e164 RETURNING id', [phone]);
      userId = res.rows[0]?.id ?? null;
    }
  }
  const payload: any = { sub: identifier, uid: userId ?? undefined };
  if (phone) payload.phone = phone;
  if (email) payload.email = email;
  const token = jwt.sign(payload, config.jwtSecret, { expiresIn: '30d' });
  return reply.send({ ok: true, phone, email, token });
});

fastify.post('/auth/register-password', async (request, reply) => {
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = passwordAuthSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const { phone, password } = parsed.data;
  const passwordHash = hashPassword(password);
  const pool = getPool();
  const res = await pool.query(
    `INSERT INTO users (phone_e164, password_hash)
     VALUES ($1, $2)
     ON CONFLICT (phone_e164) DO UPDATE SET password_hash = EXCLUDED.password_hash
     RETURNING id`,
    [phone, passwordHash]
  );
  const uid = res.rows[0]?.id ?? null;
  const token = jwt.sign({ sub: phone, phone, uid: uid ?? undefined }, config.jwtSecret, { expiresIn: '30d' });
  return reply.send({ ok: true, phone, token });
});

fastify.post('/auth/login-password', async (request, reply) => {
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = passwordAuthSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const { phone, password } = parsed.data;
  const pool = getPool();
  const res = await pool.query('SELECT id, password_hash FROM users WHERE phone_e164 = $1', [phone]);
  const row = res.rows[0];
  if (!row || !row.password_hash) {
    return reply.code(401).send({ error: 'Password not set for this phone' });
  }
  const ok = verifyPassword(password, row.password_hash);
  if (!ok) return reply.code(401).send({ error: 'Invalid credentials' });
  const token = jwt.sign({ sub: phone, phone, uid: row.id }, config.jwtSecret, { expiresIn: '30d' });
  return reply.send({ ok: true, phone, token });
});

fastify.post('/auth/register-username', async (request, reply) => {
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = usernamePasswordSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const username = parsed.data.username.toLowerCase();
  const passwordHash = hashPassword(parsed.data.password);
  const pool = getPool();
  const res = await pool.query(
    `INSERT INTO users (username, password_hash)
     VALUES ($1, $2)
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
     RETURNING id`,
    [username, passwordHash]
  );
  const uid = res.rows[0]?.id ?? null;
  const token = jwt.sign({ sub: username, username, uid: uid ?? undefined }, config.jwtSecret, { expiresIn: '30d' });
  return reply.send({ ok: true, username, token });
});

fastify.post('/auth/login-username', async (request, reply) => {
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = usernamePasswordSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: parsed.error.format() });
  }
  const username = parsed.data.username.toLowerCase();
  const password = parsed.data.password;
  const pool = getPool();
  const res = await pool.query('SELECT id, password_hash FROM users WHERE username = $1', [username]);
  const row = res.rows[0];
  if (!row || !row.password_hash) {
    return reply.code(401).send({ error: 'Password not set for this username' });
  }
  const ok = verifyPassword(password, row.password_hash);
  if (!ok) return reply.code(401).send({ error: 'Invalid credentials' });
  const token = jwt.sign({ sub: username, username, uid: row.id }, config.jwtSecret, { expiresIn: '30d' });
  return reply.send({ ok: true, username, token });
});

fastify.get('/me', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  return reply.send({ ok: true, phone: ctx.phone, email: ctx.email, username: ctx.username, uid: ctx.uid });
});

fastify.post('/settings/phone', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = linkPhoneSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.format() });
  const { phone, code } = parsed.data;
  const ok = await Promise.resolve(otpStore.verify(phone, code, config.otp.maxAttempts));
  if (!ok) return reply.code(401).send({ error: 'Invalid or expired code' });
  if (!ctx.uid) return reply.code(400).send({ error: 'User id missing' });
  const pool = getPool();
  try {
    const res = await pool.query('UPDATE users SET phone_e164 = $1 WHERE id = $2 RETURNING id', [phone, ctx.uid]);
    if (!res.rowCount) return reply.code(404).send({ error: 'User not found' });
    const token = jwt.sign({ sub: ctx.username ?? phone, phone, username: ctx.username, uid: ctx.uid }, config.jwtSecret, { expiresIn: '30d' });
    return reply.send({ ok: true, phone, token });
  } catch (err: any) {
    if (err?.code === '23505') {
      return reply.code(409).send({ error: 'Phone already linked to another account' });
    }
    request.log.error({ err }, 'Failed to link phone');
    return reply.code(500).send({ error: 'Failed to link phone' });
  }
});

fastify.get('/contacts', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  if (!ctx.uid) return reply.code(400).send({ error: 'User id missing' });
  const pool = getPool();
  const res = await pool.query('SELECT id, name, phone_e164 AS phone, address FROM contacts WHERE user_id = $1 ORDER BY created_at DESC', [ctx.uid]);
  return reply.send({ ok: true, contacts: res.rows });
});

fastify.post('/contacts', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = contactSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.format() });
  if (!ctx.uid) return reply.code(400).send({ error: 'User id missing' });
  const { name, phone, address } = parsed.data;
  const pool = getPool();
  try {
    const res = await pool.query(
      `INSERT INTO contacts (user_id, name, phone_e164, address)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, phone_e164)
       DO UPDATE SET name = EXCLUDED.name, address = EXCLUDED.address
       RETURNING id, name, phone_e164 AS phone, address`,
      [ctx.uid, name, phone, address ?? null]
    );
    return reply.send({ ok: true, contact: res.rows[0] });
  } catch (err) {
    request.log.error({ err }, 'Failed to save contact');
    return reply.code(500).send({ error: 'Failed to save contact' });
  }
});

fastify.post('/addresses', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = addAddressSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.format() });
  const { address, isDefault } = parsed.data;
  const pool = getPool();
  const uid = ctx.uid;
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
  if (!ctx.uid) return reply.code(400).send({ error: 'User not found' });
  const res = await pool.query('SELECT address, is_default FROM addresses WHERE user_id = $1', [ctx.uid]);
  return reply.send({ ok: true, addresses: res.rows });
});

fastify.post('/transfers/prepare', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = prepareTransferSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.format() });
  const { to_phone, to_address: providedAddress, amount_lamports, memo } = parsed.data;
  const pool = getPool();

  // Resolve sender and receiver
  const senderId = ctx.uid ?? null;
  if (!senderId) return reply.code(400).send({ error: 'User id missing' });
  let receiverId: number | null = null;
  let toAddress: string | null = providedAddress ?? null;
  if (to_phone) {
    const receiverRes = await pool.query('SELECT id FROM users WHERE phone_e164 = $1', [to_phone]);
    receiverId = receiverRes.rows[0]?.id ?? null;
  }
  let fromAddress: string | null = parsed.data.from_address ?? null;
  if (senderId && !fromAddress) {
    const fromAddrRes = await pool.query('SELECT address FROM addresses WHERE user_id = $1 AND is_default = TRUE LIMIT 1', [senderId]);
    fromAddress = fromAddrRes.rows[0]?.address ?? null;
  }
  if (!toAddress && receiverId) {
    const addrRes = await pool.query('SELECT address FROM addresses WHERE user_id = $1 AND is_default = TRUE LIMIT 1', [receiverId]);
    toAddress = addrRes.rows[0]?.address ?? null;
  }

  if (!fromAddress) {
    return reply.code(400).send({ error: 'Sender address not found; set a default address first' });
  }
  if (!toAddress) {
    return reply.code(400).send({ error: 'Recipient address not found' });
  }

  const lamportsBig = BigInt(amount_lamports as any);
  if (lamportsBig <= 0n) {
    return reply.code(400).send({ error: 'Amount must be positive' });
  }
  if (lamportsBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    return reply.code(400).send({ error: 'Amount too large' });
  }
  let unsignedTxBase64: string;
  let recentBlockhash: string;
  try {
    const { tx, recentBlockhash: bh } = await buildUnsignedTransfer(fromAddress, toAddress, lamportsBig, memo);
    unsignedTxBase64 = serializeUnsignedTransaction(tx);
    recentBlockhash = bh;
  } catch (err) {
    request.log.error({ err }, 'Failed to build unsigned transfer');
    return reply.code(500).send({ error: 'Failed to prepare transfer' });
  }

  const client = await pool.connect();
  let transferId: number | null = null;
  try {
    await client.query('BEGIN');
    const insert = await client.query(
      `INSERT INTO transfers (from_user, to_user, from_address, to_phone, to_address, amount_lamports, status, memo, prepared_tx_base64)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [senderId, receiverId, fromAddress, to_phone ?? null, toAddress, lamportsBig, 'prepared', memo ?? null, unsignedTxBase64]
    );
    transferId = insert.rows[0].id;
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    request.log.error({ err }, 'Failed to record prepared transfer');
    return reply.code(500).send({ error: 'Failed to record transfer' });
  }

  client.release();
  return reply.send({
    ok: true,
    transfer_id: transferId,
    from_address: fromAddress,
    to_address: toAddress,
    recent_blockhash: recentBlockhash,
    transaction_base64: unsignedTxBase64
  });
});

fastify.post('/transfers/submit', async (request, reply) => {
  const ctx = requireAuth(request, reply);
  if (!ctx) return;
  if (!useDb) return reply.code(500).send({ error: 'Database required' });
  const parsed = submitTransferSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.format() });
  const { transfer_id, signed_transaction_base64 } = parsed.data;
  const pool = getPool();
  if (!ctx.uid) return reply.code(400).send({ error: 'User id missing' });

  const rowRes = await pool.query(
    `SELECT id, status FROM transfers WHERE id = $1 AND from_user = $2`,
    [transfer_id, ctx.uid]
  );
  const transferRow = rowRes.rows[0];
  if (!transferRow) return reply.code(404).send({ error: 'Transfer not found for user' });
  if (transferRow.status !== 'prepared') return reply.code(400).send({ error: 'Transfer not in prepared state' });

  try {
    const signature = await relaySignedTransaction(signed_transaction_base64);
    await pool.query('UPDATE transfers SET status = $1, tx_signature = $2 WHERE id = $3', ['succeeded', signature, transfer_id]);
    return reply.send({ ok: true, transfer_id, status: 'succeeded', signature });
  } catch (err) {
    request.log.error({ err }, 'Broadcast failed');
    await pool.query('UPDATE transfers SET status = $1 WHERE id = $2', ['failed', transfer_id]);
    return reply.code(502).send({ error: 'On-chain broadcast failed' });
  }
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
