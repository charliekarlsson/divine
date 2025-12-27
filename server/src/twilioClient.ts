import twilio from 'twilio';
import { config, assertTwilioConfigured } from './config.js';

export function makeTwilioClient() {
  assertTwilioConfigured();
  return twilio(config.twilio.accountSid, config.twilio.authToken);
}

export async function sendOtpSms(client: twilio.Twilio, to: string, code: string) {
  const body = `Your Divine Solana verification code is ${code}`;
  await client.messages.create({
    to,
    from: config.twilio.fromNumber,
    body
  });
}
