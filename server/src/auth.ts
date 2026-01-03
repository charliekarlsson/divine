import { FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'jsonwebtoken';
import { config } from './config.js';

export interface AuthContext {
  phone?: string;
  email?: string;
  username?: string;
  uid?: number;
}

export function requireAuth(request: FastifyRequest, reply: FastifyReply): AuthContext | null {
  const auth = request.headers.authorization;
  if (!auth || !auth.toLowerCase().startsWith('bearer ')) {
    reply.code(401).send({ error: 'Unauthorized' });
    return null;
  }
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, config.jwtSecret) as any;
    return {
      phone: payload.phone as string | undefined,
      email: payload.email as string | undefined,
      username: payload.username as string | undefined,
      uid: payload.uid as number | undefined
    };
  } catch (err) {
    request.log.warn({ err }, 'Invalid token');
    reply.code(401).send({ error: 'Invalid token' });
    return null;
  }
}
