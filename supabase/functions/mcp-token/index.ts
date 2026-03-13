/**
 * MCP Token Edge Function
 *
 * POST /functions/v1/mcp-token
 * Returns a fresh JWT for accessing an asset's Wazuh MCP Server.
 * Derives the current MCP API key from the DRA chain_key (HKDF-SHA256),
 * then exchanges it for a JWT via the MCP Server's /auth/token endpoint.
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
import { decryptString, deriveTokenFromChain } from '../_shared/crypto-utils.ts';
import { safeLog, safeError } from '../_shared/logSanitization.ts';

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
      .select('mcp_chain_key, mcp_auth_token, mcp_server_url')
      .eq('id', body.asset_id)
      .single();

    if (fetchError || !asset) {
      safeError('[MCP Token] Failed to fetch asset', fetchError);
      return new Response(JSON.stringify({ error: 'Failed to fetch asset data' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    if (!asset.mcp_server_url) {
      return new Response(
        JSON.stringify({ error: 'MCP Server not configured for this asset' }),
        {
          status: 404,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // Derive current MCP token from chain_key (preferred) or use stored auth_token (legacy)
    let currentToken: string | null = null;

    if (asset.mcp_chain_key) {
      // DRA mode: derive token from chain key
      const chainKey = await decryptString(asset.mcp_chain_key, encryptionKey);
      if (chainKey) {
        currentToken = await deriveTokenFromChain(chainKey);
        safeLog('[MCP Token] Token derived from DRA chain_key');
      }
    }

    if (!currentToken && asset.mcp_auth_token) {
      // Fallback: use stored encrypted token directly
      currentToken = await decryptString(asset.mcp_auth_token, encryptionKey);
      safeLog('[MCP Token] Using stored mcp_auth_token (legacy/fallback)');
    }

    if (!currentToken) {
      safeError('[MCP Token] No MCP credentials available');
      return new Response(
        JSON.stringify({ error: 'MCP credentials not configured for this asset' }),
        {
          status: 404,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // Exchange MCP API key for JWT
    const mcpBaseUrl = asset.mcp_server_url.replace(/\/mcp\/?$/, '');
    safeLog(`[MCP Token] Exchanging token for JWT on ${mcpBaseUrl}`);

    const tokenResponse = await fetch(`${mcpBaseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: currentToken }),
    });

    if (!tokenResponse.ok) {
      await tokenResponse.text().catch(() => '');
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
