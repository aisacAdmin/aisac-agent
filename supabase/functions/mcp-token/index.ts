/**
 * MCP Token Edge Function
 *
 * POST /functions/v1/mcp-token
 * Returns a fresh JWT for accessing an asset's Wazuh MCP Server.
 * Derives the current API key from the stored seed + epoch using HMAC-SHA256
 * (DRA-inspired deterministic rotation), then exchanges it for a JWT.
 *
 * Authentication:
 *   - Authorization: Bearer <supabase-user-jwt>
 *   - apikey: <supabase-anon-key>
 *   - verify_jwt: true (Supabase validates JWT before function executes)
 *
 * Request Body:
 * {
 *   "asset_id": "uuid"   // Required: Asset ID to get MCP token for
 * }
 *
 * Response:
 * {
 *   "jwt": "eyJ...",
 *   "expires_at": "2026-03-14T...",
 *   "mcp_server_url": "http://host:3000/mcp"
 * }
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.3';
import { getCorsHeaders, handleCorsPreflight } from '../_shared/cors.ts';
import { decryptString } from '../_shared/crypto-utils.ts';
import { safeLog, safeError } from '../_shared/logSanitization.ts';

// ============================================================================
// Token Derivation (DRA-inspired)
// ============================================================================

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToB64Url(bytes: Uint8Array): string {
  const binString = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
  const b64 = btoa(binString);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Derive the current MCP API key from seed + epoch using HMAC-SHA256.
 * token_n = HMAC-SHA256(seed, "mcp-token-rotation:" + rotation_count)
 * rotation_count = floor((now - epoch) / 86400)
 */
async function deriveCurrentToken(
  seedHex: string,
  epochSeconds: number,
  rotationOffset: number = 0
): Promise<string> {
  const rotationCount = Math.max(
    0,
    Math.floor((Date.now() / 1000 - epochSeconds) / 86400) + rotationOffset
  );
  const seedBytes = hexToBytes(seedHex);
  const data = new TextEncoder().encode(`mcp-token-rotation:${rotationCount}`);

  const key = await crypto.subtle.importKey(
    'raw',
    seedBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
  return `wazuh_${bytesToB64Url(sig)}`;
}

// ============================================================================
// Rate Limiting
// ============================================================================

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(key: string): boolean {
  const now = Date.now();
  const limit = 30;
  const windowMs = 60_000;

  let bucket = rateLimitStore.get(key);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateLimitStore.set(key, bucket);
  }

  bucket.count++;
  return bucket.count <= limit;
}

// ============================================================================
// Main Handler
// ============================================================================

serve(async req => {
  if (req.method === 'OPTIONS') {
    return handleCorsPreflight(req);
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  try {
    // Rate limit by IP
    const clientIp =
      req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      req.headers.get('x-real-ip') ||
      'unknown';

    if (!checkRateLimit(clientIp)) {
      return new Response(
        JSON.stringify({ error: 'Rate limit exceeded', retry_after_seconds: 60 }),
        {
          status: 429,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    safeLog('[MCP Token] Request received');

    // Parse request body
    let body: { asset_id?: string };
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
        status: 400,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    if (!body.asset_id) {
      return new Response(JSON.stringify({ error: 'asset_id is required' }), {
        status: 400,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Initialize Supabase clients
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    const encryptionKey = Deno.env.get('ENCRYPTION_KEY');

    if (!supabaseUrl || !serviceRoleKey || !encryptionKey) {
      safeError('[MCP Token] Missing server configuration');
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Create client with user's JWT to verify access (RLS)
    const authHeader = req.headers.get('Authorization') || '';
    const userJwt = authHeader.replace(/^Bearer\s+/i, '');

    const userClient = createClient(supabaseUrl, Deno.env.get('SUPABASE_ANON_KEY') || serviceRoleKey, {
      global: { headers: { Authorization: `Bearer ${userJwt}` } },
    });

    // Verify user has access to this asset via RLS
    const { data: assetCheck, error: accessError } = await userClient
      .from('monitored_assets')
      .select('id')
      .eq('id', body.asset_id)
      .single();

    if (accessError || !assetCheck) {
      safeLog(`[MCP Token] Access denied or asset not found: ${body.asset_id}`);
      return new Response(
        JSON.stringify({ error: 'Asset not found or access denied' }),
        {
          status: 403,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // Use service role to read encrypted fields
    const serviceClient = createClient(supabaseUrl, serviceRoleKey);
    const { data: asset, error: fetchError } = await serviceClient
      .from('monitored_assets')
      .select('mcp_auth_seed, mcp_rotation_epoch, mcp_server_url')
      .eq('id', body.asset_id)
      .single();

    if (fetchError || !asset) {
      safeError('[MCP Token] Failed to fetch asset', fetchError);
      return new Response(JSON.stringify({ error: 'Failed to fetch asset data' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    if (!asset.mcp_auth_seed || !asset.mcp_rotation_epoch || !asset.mcp_server_url) {
      return new Response(
        JSON.stringify({ error: 'MCP Server not configured for this asset' }),
        {
          status: 404,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // Decrypt seed
    const seed = await decryptString(asset.mcp_auth_seed, encryptionKey);
    if (!seed) {
      safeError('[MCP Token] Failed to decrypt seed');
      return new Response(JSON.stringify({ error: 'Failed to decrypt MCP credentials' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Derive current token and exchange for JWT
    const mcpBaseUrl = asset.mcp_server_url.replace(/\/mcp\/?$/, '');
    const currentToken = await deriveCurrentToken(seed, asset.mcp_rotation_epoch);

    safeLog(`[MCP Token] Exchanging derived token for JWT on ${mcpBaseUrl}`);

    let tokenResponse = await fetch(`${mcpBaseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: currentToken }),
    });

    // Grace period: if 401, try previous rotation count
    if (tokenResponse.status === 401) {
      safeLog('[MCP Token] Current token rejected, trying previous rotation (grace period)');
      const previousToken = await deriveCurrentToken(seed, asset.mcp_rotation_epoch, -1);
      tokenResponse = await fetch(`${mcpBaseUrl}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: previousToken }),
      });
    }

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text().catch(() => 'Unknown error');
      safeError(`[MCP Token] MCP Server rejected token exchange: ${tokenResponse.status}`);
      return new Response(
        JSON.stringify({
          error: 'Failed to obtain JWT from MCP Server',
          detail: `MCP Server returned ${tokenResponse.status}`,
        }),
        {
          status: 502,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    const tokenData = await tokenResponse.json();

    // Calculate expiration
    const expiresAt = new Date(Date.now() + (tokenData.expires_in || 86400) * 1000).toISOString();

    safeLog(`[MCP Token] JWT obtained for asset ${body.asset_id}`);

    return new Response(
      JSON.stringify({
        jwt: tokenData.access_token,
        expires_at: expiresAt,
        mcp_server_url: asset.mcp_server_url,
      }),
      {
        status: 200,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    safeError('[MCP Token] Unhandled error', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
});
