import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from 'jsonwebtoken';
import { config } from './config.js';
import { InMemoryOtpStore } from './otpStore.js';
import { PgOtpStore } from './pgOtpStore.js';
import { requestOtpSchema, verifyOtpSchema } from './schema.js';
import { makeTwilioClient, sendOtpSms } from './twilioClient.js';
import { getPool, runMigrations } from './db.js';

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
