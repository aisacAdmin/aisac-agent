/**
 * List MCP Assets Edge Function
 *
 * Returns the authenticated user's assets that have MCP Server configured.
 * Used by AI agents to dynamically discover available MCP endpoints.
 *
 * GET /functions/v1/list-mcp-assets
 * Authorization: Bearer <supabase-user-jwt>
 * apikey: <supabase-anon-key>
 *
 * verify_jwt: true — requires authenticated Supabase user
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { handleCorsPreflight, getCorsHeaders } from '../_shared/cors.ts';
import { safeLog, safeError } from '../_shared/logSanitization.ts';

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  let bucket = rateLimitStore.get(ip);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + 60_000 };
    rateLimitStore.set(ip, bucket);
  }
  bucket.count++;
  return bucket.count <= 30;
}

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return handleCorsPreflight(req);
  }

  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  try {
    const clientIp =
      req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      req.headers.get('x-real-ip') ||
      'unknown';

    if (!checkRateLimit(clientIp)) {
      return new Response(
        JSON.stringify({ error: 'Rate limit exceeded', retry_after_seconds: 60 }),
        { status: 429, headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' } }
      );
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY');

    if (!supabaseUrl || !anonKey) {
      safeError('[list-mcp-assets] Missing server configuration');
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Create client with user's JWT — RLS filters by tenant automatically
    const authHeader = req.headers.get('Authorization') || '';
    const userJwt = authHeader.replace(/^Bearer\s+/i, '');

    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${userJwt}` } },
    });

    // Query assets with MCP configured (RLS ensures tenant isolation)
    const { data: assets, error: queryError } = await userClient
      .from('monitored_assets')
      .select('id, name, status, mcp_server_url, cf_tunnel_hostname')
      .not('mcp_server_url', 'is', null)
      .order('name');

    if (queryError) {
      safeError('[list-mcp-assets] Query failed', queryError);
      return new Response(JSON.stringify({ error: 'Failed to fetch assets' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    const result = (assets || []).map((asset) => ({
      id: asset.id,
      name: asset.name,
      status: asset.status,
      mcp_url: asset.mcp_server_url,
      tunnel_active: !!asset.cf_tunnel_hostname,
    }));

    safeLog(`[list-mcp-assets] Returned ${result.length} assets`);

    return new Response(JSON.stringify({ assets: result }), {
      status: 200,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  } catch (error) {
    safeError('[list-mcp-assets] Unhandled error', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
});
