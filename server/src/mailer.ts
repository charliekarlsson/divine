import { ServerClient } from 'postmark';
import { config, assertPostmarkConfigured } from './config.js';

export function makePostmarkClient() {
  assertPostmarkConfigured();
  return new ServerClient(config.postmark.serverToken);
}

export async function sendOtpEmail(client: ServerClient, to: string, code: string) {
  if (!config.postmark.fromEmail) {
    throw new Error('POSTMARK_FROM_EMAIL is required');
  }
  const minutes = Math.max(1, Math.round(config.otp.ttlMs / 60000));
  const text = `Your verification code is ${code}. It expires in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
  await client.sendEmail({
    From: config.postmark.fromEmail,
    To: to,
    Subject: 'Your Dash verification code',
    TextBody: text,
    MessageStream: config.postmark.messageStream || 'outbound'
  });
}
