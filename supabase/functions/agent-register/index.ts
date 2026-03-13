/**
 * Agent Register Edge Function
 *
 * POST /v1/register
 * Registers a new AISAC agent associated with an existing asset in the platform.
 * Optionally registers Command Server credentials (encrypted at rest).
 *
 * Authentication:
 *   - Header: X-API-Key: aisac_xxx (preferred)
 *   - Header: Authorization: Bearer aisac_xxx (also supported)
 *
 * Request Body:
 * {
 *   "agent_id": "agent-hostname-abc123",  // Required: Unique agent ID
 *   "asset_id": "uuid",                   // Required: Asset ID to associate
 *   "hostname": "server-01",              // Required: Hostname
 *   "os": "debian",                       // Optional: OS type
 *   "os_version": "13",                   // Optional: OS version
 *   "arch": "x86_64",                     // Optional: Architecture
 *   "kernel": "6.1.0-18-amd64",          // Optional: Kernel version
 *   "ip_address": "192.168.1.100",       // Optional: IP address
 *   "version": "1.0.1",                  // Optional: Agent version
 *   "capabilities": ["collector", "soar"] // Optional: Agent capabilities
 *   "command_server": {                   // Optional: Command Server credentials
 *     "api_token": "secret-token",        //   Required if command_server present
 *     "url": "https://localhost:8443",    //   Optional: CS URL
 *     "version": "2.1.0"                 //   Optional: CS version
 *   },
 *   "mcp_server": {                       // Optional: MCP Server credentials
 *     "auth_token": "wazuh_xxx",          //   Current wazuh API key (legacy, optional with DH)
 *     "dh_public_key": "base64url",       //   Agent's X25519 DH public key for DRA
 *     "seed": "hex-seed",                 //   DRA seed backup (optional)
 *     "rotation_epoch": 1773561600,       //   Unix epoch for rotation calc
 *     "url": "http://host:3000"           //   Optional: MCP Server URL
 *   }
 * }
 *
 * Response Codes:
 *   200/201: Registration successful
 *   400: Bad request (missing required fields)
 *   401: Invalid API Key
 *   403: No permission to register on this asset
 *   404: Asset not found
 *   409: Agent ID already registered (can continue)
 *   500: Internal server error
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.3';
import { getCorsHeaders, handleCorsPreflight } from '../_shared/cors.ts';
import {
  encryptString,
  generateX25519Keypair,
  computeSharedSecret,
  initializeDRA,
} from '../_shared/crypto-utils.ts';
import { safeLog, safeError } from '../_shared/logSanitization.ts';

interface CommandServerInfo {
  api_token: string;
  url?: string;
  version?: string;
}

interface McpServerInfo {
  auth_token?: string;
  dh_public_key?: string;
  seed?: string;
  rotation_epoch?: number;
  url?: string;
}

interface RegisterRequest {
  agent_id: string;
  asset_id: string;
  hostname: string;
  os?: string;
  os_version?: string;
  arch?: string;
  kernel?: string;
  ip_address?: string;
  version?: string;
  capabilities?: string[];
  command_server?: CommandServerInfo;
  mcp_server?: McpServerInfo;
}

interface AssetValidation {
  asset_id: string;
  tenant_id: string;
  asset_name: string;
  is_valid: boolean;
}

// ============================================================================
// Rate Limiting (per IP, 30 req/min — tighter than webhook since registration is infrequent)
// ============================================================================

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const limit = 30;
  const windowMs = 60_000;

  let bucket = rateLimitStore.get(ip);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateLimitStore.set(ip, bucket);
  }

  bucket.count++;
  const remaining = Math.max(0, limit - bucket.count);
  return { allowed: bucket.count <= limit, remaining };
}

/**
 * Extract API Key from request headers
 * Supports both X-API-Key and Authorization: Bearer formats
 */
function extractApiKey(req: Request): string | null {
  // Priority 1: X-API-Key header (per specification)
  const xApiKey = req.headers.get('X-API-Key');
  if (xApiKey && xApiKey.startsWith('aisac_')) {
    return xApiKey;
  }

  // Priority 2: Authorization: Bearer header (backwards compatibility)
  const authHeader = req.headers.get('Authorization');
  if (authHeader) {
    const bearerMatch = authHeader.match(/^Bearer\s+(aisac_\S+)$/i);
    if (bearerMatch) {
      return bearerMatch[1];
    }
  }

  return null;
}

/**
 * Validate IP address format (IPv4)
 */
function isValidIPv4(ip: string): boolean {
  const ipv4Regex =
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

/**
 * Validate UUID format
 */
function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

serve(async req => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return handleCorsPreflight(req);
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  try {
    // ── Rate limiting ───────────────────────────────────────────────────
    const clientIp =
      req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      req.headers.get('x-real-ip') ||
      'unknown';

    const rateCheck = checkRateLimit(clientIp);
    if (!rateCheck.allowed) {
      safeLog(`[Agent Register] Rate limit exceeded for IP: ${clientIp}`);
      return new Response(
        JSON.stringify({ error: 'Rate limit exceeded', retry_after_seconds: 60 }),
        {
          status: 429,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    safeLog('[Agent Register] Request received');

    // 1. Extract API Key from headers
    const apiKey = extractApiKey(req);

    if (!apiKey) {
      safeLog('[Agent Register] Missing or invalid API Key');
      return new Response(
        JSON.stringify({
          error: 'API Key required',
          message: 'Use header X-API-Key: aisac_xxx',
        }),
        {
          status: 401,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // 2. Initialize Supabase with service role
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

    if (!supabaseUrl || !serviceRoleKey) {
      safeError('[Agent Register] Missing Supabase configuration');
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    const supabase = createClient(supabaseUrl, serviceRoleKey);

    // 3. Parse and validate request body
    let body: RegisterRequest;
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON in request body' }), {
        status: 400,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Validate required fields
    const missingFields: string[] = [];
    if (!body.agent_id) missingFields.push('agent_id');
    if (!body.asset_id) missingFields.push('asset_id');
    if (!body.hostname) missingFields.push('hostname');

    if (missingFields.length > 0) {
      return new Response(
        JSON.stringify({
          error: 'Missing required fields',
          missing: missingFields,
        }),
        {
          status: 400,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // Validate asset_id format
    if (!isValidUUID(body.asset_id)) {
      return new Response(
        JSON.stringify({
          error: 'Invalid asset_id format',
          message: 'asset_id must be a valid UUID',
        }),
        {
          status: 400,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // 4. Validate API Key using existing function
    safeLog('[Agent Register] Validating API Key...');
    const { data: validation, error: validationError } = await supabase.rpc(
      'validate_asset_api_key',
      { p_api_key: apiKey }
    );

    if (validationError) {
      safeError('[Agent Register] Validation error', validationError);
      return new Response(
        JSON.stringify({
          error: 'API Key validation failed',
        }),
        {
          status: 500,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // RPC returns an array, get first item
    const assetValidation = (validation as AssetValidation[])?.[0];

    // Check if API key is valid at all
    if (!assetValidation) {
      safeLog('[Agent Register] Invalid API Key - no asset found');
      return new Response(JSON.stringify({ error: 'Invalid API Key' }), {
        status: 401,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Check if asset exists but is disabled
    if (!assetValidation.is_valid) {
      safeLog('[Agent Register] Asset is disabled or decommissioned');
      return new Response(JSON.stringify({ error: 'Asset is disabled or decommissioned' }), {
        status: 403,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // 5. Verify asset_id matches the API key's asset
    if (body.asset_id !== assetValidation.asset_id) {
      // Check if the provided asset_id exists at all
      const { data: assetExists } = await supabase
        .from('monitored_assets')
        .select('id')
        .eq('id', body.asset_id)
        .single();

      if (!assetExists) {
        safeLog(`[Agent Register] Asset not found: ${body.asset_id}`);
        return new Response(
          JSON.stringify({
            error: 'Asset not found',
            asset_id: body.asset_id,
          }),
          {
            status: 404,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }

      // Asset exists but API key doesn't have permission
      safeLog('[Agent Register] API Key does not match asset_id');
      return new Response(
        JSON.stringify({
          error: 'No permission to register on this asset',
          message: 'API Key does not match the provided asset_id',
        }),
        {
          status: 403,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    safeLog(
      `[Agent Register] API Key valid for asset: ${assetValidation.asset_name} (${assetValidation.asset_id})`
    );

    // 6. Check if agent_id is already registered
    const { data: existingAgent } = await supabase
      .from('monitored_assets')
      .select('id, name, agent_id')
      .eq('agent_id', body.agent_id)
      .single();

    if (existingAgent) {
      // If same asset, this is a re-registration (allowed)
      if (existingAgent.id === assetValidation.asset_id) {
        safeLog(`[Agent Register] Re-registering agent ${body.agent_id} on same asset`);
        // Continue to update
      } else {
        // Different asset - conflict
        safeLog(`[Agent Register] Agent ID already registered to: ${existingAgent.name}`);
        return new Response(
          JSON.stringify({
            success: false,
            error: 'Agent ID already registered',
            message: `Agent ID is already registered to another asset: ${existingAgent.name}`,
            existing_asset: existingAgent.name,
          }),
          {
            status: 409,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }
    }

    // 7. Prepare update data
    const updateData: Record<string, unknown> = {
      agent_id: body.agent_id,
      hostname: body.hostname,
      agent_last_seen: new Date().toISOString(),
      last_heartbeat: new Date().toISOString(),
      status: 'online',
      consecutive_failures: 0,
    };

    // Add optional fields if provided
    if (body.os) updateData.os_type = body.os;
    if (body.os_version) updateData.os_version = body.os_version;
    if (body.arch) updateData.arch = body.arch;
    if (body.kernel) updateData.kernel = body.kernel;
    if (body.version) updateData.agent_version = body.version;

    // Validate and add IP address
    if (body.ip_address) {
      if (isValidIPv4(body.ip_address)) {
        updateData.ip_address = body.ip_address;
      } else {
        safeLog(`[Agent Register] Invalid IP address format: ${body.ip_address}`);
      }
    }

    // Add capabilities if provided
    if (body.capabilities && Array.isArray(body.capabilities)) {
      // Filter to valid capability values
      const validCapabilities = ['collector', 'soar', 'heartbeat'];
      const filteredCapabilities = body.capabilities.filter(cap => validCapabilities.includes(cap));
      updateData.capabilities = filteredCapabilities;
    }

    // Handle Command Server registration (optional)
    let commandServerRegistered = false;
    if (body.command_server) {
      const cs = body.command_server;

      // Validate api_token is present
      if (!cs.api_token || typeof cs.api_token !== 'string' || cs.api_token.length < 1) {
        return new Response(
          JSON.stringify({
            error: 'Invalid command_server.api_token',
            message: 'api_token is required when command_server is provided',
          }),
          {
            status: 400,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }

      // Validate token length (max 1000 chars)
      if (cs.api_token.length > 1000) {
        return new Response(
          JSON.stringify({ error: 'command_server.api_token exceeds maximum length (1000)' }),
          {
            status: 400,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }

      // Encrypt the Command Server token with ENCRYPTION_KEY (AES-256-GCM)
      const encryptionKey = Deno.env.get('ENCRYPTION_KEY');
      if (!encryptionKey) {
        safeError('[Agent Register] Missing ENCRYPTION_KEY for Command Server token encryption');
        return new Response(
          JSON.stringify({ error: 'Server configuration error: encryption not available' }),
          {
            status: 500,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }

      try {
        const encryptedToken = await encryptString(cs.api_token, encryptionKey);
        updateData.command_server_token = encryptedToken;
        if (cs.url) updateData.command_server_url = cs.url;
        if (cs.version) updateData.command_server_version = cs.version;
        commandServerRegistered = true;
        safeLog(
          `[Agent Register] Command Server credentials encrypted for asset ${assetValidation.asset_id}`
        );
      } catch (encError) {
        safeError('[Agent Register] Failed to encrypt Command Server token', encError);
        return new Response(
          JSON.stringify({ error: 'Failed to encrypt Command Server credentials' }),
          {
            status: 500,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }
    }

    // Handle MCP Server registration (optional)
    let mcpServerRegistered = false;
    let platformDhPublicKey: string | undefined;
    if (body.mcp_server) {
      const mcp = body.mcp_server;

      // Require either auth_token (legacy) or dh_public_key (DRA)
      if (!mcp.auth_token && !mcp.dh_public_key) {
        return new Response(
          JSON.stringify({
            error: 'Invalid mcp_server',
            message: 'Either auth_token or dh_public_key is required when mcp_server is provided',
          }),
          {
            status: 400,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }

      const encryptionKey = Deno.env.get('ENCRYPTION_KEY');
      if (!encryptionKey) {
        safeError('[Agent Register] Missing ENCRYPTION_KEY for MCP token encryption');
        return new Response(
          JSON.stringify({ error: 'Server configuration error: encryption not available' }),
          {
            status: 500,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }

      try {
        if (mcp.url) updateData.mcp_server_url = mcp.url;
        updateData.mcp_server_updated_at = new Date().toISOString();
        updateData.mcp_rotation_epoch = mcp.rotation_epoch || Math.floor(Date.now() / 1000);

        // Store seed backup if provided
        if (mcp.seed) {
          const encryptedSeed = await encryptString(mcp.seed, encryptionKey);
          updateData.mcp_auth_seed = encryptedSeed;
        }

        if (mcp.dh_public_key) {
          // ── DRA mode: X25519 DH key exchange ──────────────────────────
          safeLog('[Agent Register] DRA mode: performing X25519 DH key exchange');

          // Generate platform's X25519 keypair
          const platformKeypair = generateX25519Keypair();
          platformDhPublicKey = platformKeypair.publicKey;

          // Compute shared secret: X25519(platform_priv, agent_pub)
          const sharedSecret = computeSharedSecret(
            platformKeypair.privateKey,
            mcp.dh_public_key
          );

          // Initialize DRA: derive root_key, chain_key, initial mcp_token
          const dra = await initializeDRA(sharedSecret);

          // Store platform's DH keys (private encrypted, public plaintext)
          updateData.mcp_dh_public_key = platformKeypair.publicKey;
          updateData.mcp_dh_private_key = await encryptString(platformKeypair.privateKey, encryptionKey);
          updateData.mcp_agent_dh_public_key = mcp.dh_public_key;

          // Store DRA state (encrypted)
          updateData.mcp_root_key = await encryptString(dra.rootKey, encryptionKey);
          updateData.mcp_chain_key = await encryptString(dra.chainKey, encryptionKey);

          // Store the derived initial token (encrypted)
          updateData.mcp_auth_token = await encryptString(dra.mcpToken, encryptionKey);

          safeLog(
            `[Agent Register] DRA initialized for asset ${assetValidation.asset_id}, ` +
            `initial token: ${dra.mcpToken.substring(0, 10)}...`
          );
        } else if (mcp.auth_token) {
          // ── Legacy mode: direct token storage ─────────────────────────
          if (mcp.auth_token.length > 1000) {
            return new Response(
              JSON.stringify({ error: 'mcp_server.auth_token exceeds maximum length (1000)' }),
              {
                status: 400,
                headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
              }
            );
          }

          const encryptedToken = await encryptString(mcp.auth_token, encryptionKey);
          updateData.mcp_auth_token = encryptedToken;
          safeLog('[Agent Register] MCP token stored (legacy mode)');
        }

        mcpServerRegistered = true;
        safeLog(
          `[Agent Register] MCP Server credentials stored for asset ${assetValidation.asset_id}`
        );
      } catch (encError) {
        safeError('[Agent Register] Failed to process MCP credentials', encError);
        return new Response(
          JSON.stringify({ error: 'Failed to process MCP Server credentials' }),
          {
            status: 500,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }
    }

    // 8. Update monitored_assets with agent info
    safeLog(`[Agent Register] Registering agent: ${body.agent_id}`);

    const { error: updateError } = await supabase
      .from('monitored_assets')
      .update(updateData)
      .eq('id', assetValidation.asset_id);

    if (updateError) {
      safeError('[Agent Register] Update failed', updateError);
      return new Response(
        JSON.stringify({
          error: 'Failed to register agent',
        }),
        {
          status: 500,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    const isNewRegistration = !existingAgent;
    safeLog(
      `[Agent Register] Successfully ${isNewRegistration ? 'registered' : 're-registered'} agent ${body.agent_id} for asset ${assetValidation.asset_name}`
    );

    const responseBody: Record<string, unknown> = {
      success: true,
      agent_id: body.agent_id,
      message: 'Agent registered successfully',
      command_server_registered: commandServerRegistered,
      mcp_server_registered: mcpServerRegistered,
    };

    // Return platform's DH public key so agent can complete DRA initialization
    if (platformDhPublicKey) {
      responseBody.mcp_dh_public_key = platformDhPublicKey;
    }

    return new Response(
      JSON.stringify(responseBody),
      {
        status: isNewRegistration ? 201 : 200,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    safeError('[Agent Register] Unhandled error', error);
    return new Response(
      JSON.stringify({
        error: 'Internal server error',
      }),
      {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      }
    );
  }
});
