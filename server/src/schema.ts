import { z } from 'zod';

export const phoneSchema = z.string().regex(/^\+?[1-9]\d{6,14}$/i, 'Phone must be E.164');

export const requestOtpSchema = z.object({
  phone: phoneSchema
});

export const verifyOtpSchema = z.object({
  phone: phoneSchema,
  code: z.string().length(6)
});

export const addAddressSchema = z.object({
  address: z.string().min(10, 'Address required'),
  isDefault: z.boolean().optional()
});

export const transferSchema = z.object({
  to_phone: phoneSchema,
  amount_lamports: z.bigint().or(z.number().int().positive()),
  memo: z.string().max(120).optional()
});
