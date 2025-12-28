import dotenv from 'dotenv';

dotenv.config();

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var ${name}`);
  return v;
}

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT || 4000),
  twilio: {
    accountSid: process.env.TWILIO_ACCOUNT_SID || '',
    authToken: process.env.TWILIO_AUTH_TOKEN || '',
    fromNumber: process.env.TWILIO_FROM_NUMBER || ''
  },
  otp: {
    ttlMs: Number(process.env.OTP_TTL_MS || 5 * 60 * 1000),
    maxAttempts: Number(process.env.OTP_MAX_ATTEMPTS || 5)
  },
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-me',
  solana: {
    rpcUrl: process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com',
    secretKey: process.env.SOLANA_SECRET_KEY || ''
  }
};

export function assertTwilioConfigured() {
  if (!config.twilio.accountSid || !config.twilio.authToken || !config.twilio.fromNumber) {
    throw new Error('Twilio is not fully configured (accountSid/authToken/fromNumber).');
  }
}
