const memoryCache = new Map<string, { lamports: number; expiresAt: number }>();

const respond = (status: number, body: any) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });

const parseHeaders = (raw: unknown) => {
  if (typeof raw !== 'string' || !raw.trim()) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      return Object.entries(parsed as Record<string, unknown>).reduce<Record<string, string>>((acc, [key, value]) => {
        if (typeof value === 'string') acc[key] = value;
        return acc;
      }, {});
    }
  } catch {
    const pairs = raw.split(',');
    return pairs.reduce<Record<string, string>>((acc, pair) => {
      const [name, ...rest] = pair.split('=');
      const headerName = name?.trim();
      const headerValue = rest.join('=').trim();
      if (headerName && headerValue) acc[headerName] = headerValue;
      return acc;
    }, {});
  }
  return {};
};

const lowerCaseKeys = (headers: Record<string, string>) =>
  Object.keys(headers).reduce<Record<string, string>>((acc, key) => {
    acc[key.toLowerCase()] = key;
    return acc;
  }, {});

const buildRpcRequest = (context: { env: Record<string, unknown> | undefined }, rpcOverride: string | null) => {
  const envEndpoint = context.env?.SOLANA_RPC;
  const baseEndpoint = rpcOverride || (typeof envEndpoint === 'string' ? envEndpoint.trim() : undefined);
  if (!baseEndpoint) {
    return {
      error: respond(500, { error: 'RPC endpoint not configured', hint: 'Set SOLANA_RPC env var or pass ?rpc=' })
    } as const;
  }

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const extraHeaders = parseHeaders(context.env?.SOLANA_RPC_HEADERS);
  for (const [key, value] of Object.entries(extraHeaders)) {
    headers[key] = value;
  }

  let requestUrl = baseEndpoint;
  const rawKey = context.env?.SOLANA_RPC_KEY ?? context.env?.HELIUS_API_KEY;
  const apiKey = typeof rawKey === 'string' ? rawKey.trim() : undefined;
  if (!rpcOverride && apiKey) {
    const headerKeys = lowerCaseKeys(headers);
    const hasAuthHeader = 'authorization' in headerKeys || 'api-key' in headerKeys;
    if (!hasAuthHeader) {
      headers['api-key'] = apiKey;
    }
    if (!requestUrl.includes('api-key=')) {
      try {
        const url = new URL(requestUrl);
        url.searchParams.set('api-key', apiKey);
        requestUrl = url.toString();
      } catch {
        // ignore malformed url, fetch will surface the error later
      }
    }
  }

  return { url: requestUrl, headers } as const;
};

export const onRequest: PagesFunction = async (context) => {
  const url = new URL(context.request.url);
  const address = url.searchParams.get('address');
  const rpcOverride = url.searchParams.get('rpc')?.trim() || null;

  if (!address) {
    return respond(400, { error: 'address is required' });
  }

  if (!/^([1-9A-HJ-NP-Za-km-z]{32,44})$/.test(address)) {
    return respond(400, { error: 'address must be base58', address });
  }

  const now = Date.now();
  const cached = memoryCache.get(address);
  if (cached && cached.expiresAt > now) {
    return respond(200, { ok: true, lamports: cached.lamports, source: 'cache' });
  }

  const requestConfig = buildRpcRequest(context, rpcOverride);
  if ('error' in requestConfig) return requestConfig.error;

  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: 'get-balance',
    method: 'getBalance',
    params: [address, { commitment: 'finalized' }]
  });

  let response: Response;
  try {
    response = await fetch(requestConfig.url, {
      method: 'POST',
      headers: requestConfig.headers,
      body
    });
  } catch (err: any) {
    return respond(502, {
      error: 'rpc_unreachable',
      detail: err?.message || String(err),
      rpc: requestConfig.url
    });
  }

  let payload: any = null;
  let payloadText: string | null = null;
  try {
    payloadText = await response.text();
    payload = payloadText ? JSON.parse(payloadText) : null;
  } catch {
    // leave payload as null; text captured for debugging
  }

  if (!response.ok) {
    return respond(response.status, {
      error: 'rpc_error',
      rpc: requestConfig.url,
      body: payload ?? payloadText ?? null
    });
  }

  if (!payload) {
    return respond(502, { error: 'invalid_json', rpc: requestConfig.url, body: payloadText ?? null });
  }

  if (payload?.error) {
    return respond(502, { error: 'rpc_response_error', rpc: requestConfig.url, body: payload.error });
  }

  const lamports = payload?.result?.value;
  if (typeof lamports !== 'number') {
    return respond(502, { error: 'unexpected_rpc_response', rpc: requestConfig.url, body: payload });
  }

  memoryCache.set(address, { lamports, expiresAt: now + 60_000 });
  return respond(200, { ok: true, lamports, rpc: requestConfig.url, source: 'rpc' });
};
