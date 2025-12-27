import Fastify from 'fastify';
import cors from '@fastify/cors';
import { config } from './config.js';
import { InMemoryOtpStore } from './otpStore.js';
import { requestOtpSchema, verifyOtpSchema } from './schema.js';
import { makeTwilioClient, sendOtpSms } from './twilioClient.js';

const otpStore = new InMemoryOtpStore();
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
  otpStore.issue(phone, code, config.otp.ttlMs);

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
  const ok = otpStore.verify(phone, code, config.otp.maxAttempts);
  if (!ok) {
    return reply.code(401).send({ error: 'Invalid or expired code' });
  }
  // TODO: create or fetch user, issue session/JWT, map phone->address.
  return reply.send({ ok: true, phone });
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
