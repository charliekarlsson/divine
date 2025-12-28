import { z } from 'zod';

export const phoneSchema = z.string().regex(/^\+?[1-9]\d{6,14}$/i, 'Phone must be E.164');

export const usernameSchema = z.string().min(3).max(32).regex(/^[a-zA-Z0-9._-]+$/, 'Username is alphanumeric with . _ -');

export const requestOtpSchema = z.object({
  phone: phoneSchema
});

export const verifyOtpSchema = z.object({
  phone: phoneSchema,
  code: z.string().length(6)
});

export const passwordAuthSchema = z.object({
  phone: phoneSchema,
  password: z.string().min(6).max(128)
});

export const usernamePasswordSchema = z.object({
  username: usernameSchema,
  password: z.string().min(6).max(128)
});

export const addAddressSchema = z.object({
  address: z.string().min(10, 'Address required'),
  isDefault: z.boolean().optional()
});

export const linkPhoneSchema = z.object({
  phone: phoneSchema,
  code: z.string().length(6)
});

export const contactSchema = z.object({
  name: z.string().min(1).max(120),
  phone: phoneSchema,
  address: z.string().min(10).optional()
});

export const prepareTransferSchema = z.object({
  to_phone: phoneSchema,
  to_address: z.string().min(10).optional(),
  amount_lamports: z.bigint().or(z.number().int().positive()),
  memo: z.string().max(120).optional(),
  from_address: z.string().min(10).optional()
});

export const submitTransferSchema = z.object({
  transfer_id: z.number().int().positive(),
  signed_transaction_base64: z.string().min(20)
});
