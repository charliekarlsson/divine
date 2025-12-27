import { z } from 'zod';

export const phoneSchema = z.string().regex(/^\+?[1-9]\d{6,14}$/i, 'Phone must be E.164');

export const requestOtpSchema = z.object({
  phone: phoneSchema
});

export const verifyOtpSchema = z.object({
  phone: phoneSchema,
  code: z.string().length(6)
});
