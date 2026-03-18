import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { getCorsHeaders, handleCorsPreflight } from '../_shared/cors.ts';
import {
  encryptString,
  decryptString,
  generateX25519Keypair,
  computeSharedSecret,
  ratchetStep,
  deriveTokenFromChain,
} from '../_shared/crypto-utils.ts';
import { safeLog, safeError } from '../_shared/logSanitization.ts';

// Rate limiting: max heartbeats per minute per asset
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

// In-memory rate limiting (resets on function cold start)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(assetId: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(assetId);

  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(assetId, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }

  if (entry.count >= RATE_LIMIT_MAX) {
    return false;
  }

  entry.count++;
  return true;
}

// Heartbeat intervals based on criticality (in seconds)
const HEARTBEAT_INTERVALS: Record<string, number> = {
  critical: 60,
  high: 90,
  medium: 120,
  low: 180,
};

interface HeartbeatPayload {
  asset_id: string;
  timestamp: string;
  agent_version: string;
  dh_public_key?: string; // Agent's new ephemeral X25519 DH public key for ratchet step
  metrics?: {
    cpu_percent?: number;
    memory_percent?: number;
    disk_percent?: number;
    uptime_seconds?: number;
    network?: {
      bytes_sent?: number;
      bytes_recv?: number;
    };
  };
  status?: {
    services_running?: string[];
    last_log_sent?: string;
    errors?: string[];
  };
}

serve(async (req: Request) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return handleCorsPreflight(req);
  }

  try {
    // 1. Extract and validate API Key from X-API-Key header
    const apiKey = req.headers.get('X-API-Key');
    if (!apiKey) {
      return new Response(JSON.stringify({ error: 'Missing X-API-Key header' }), {
        status: 401,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Validate API key format
    const validAkFormat = apiKey.startsWith('ak_') && apiKey.length === 66;
    const validAisacFormat = apiKey.startsWith('aisac_') && apiKey.length === 54;
    if (!validAkFormat && !validAisacFormat) {
      return new Response(
        JSON.stringify({ error: 'Invalid API key format. Expected: ak_<64 hex chars> or aisac_<48 hex chars>' }),
        { status: 401, headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' } }
      );
    }

    // 2. Parse and validate payload
    let payload: HeartbeatPayload;
    try {
      payload = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON payload' }), {
        status: 400,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Basic validation
    if (!payload.asset_id || typeof payload.asset_id !== 'string') {
      return new Response(JSON.stringify({ error: 'Missing or invalid asset_id' }), {
        status: 400,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Validate metrics if provided
    if (payload.metrics) {
      const { cpu_percent, memory_percent, disk_percent } = payload.metrics;
      if (cpu_percent !== undefined && (cpu_percent < 0 || cpu_percent > 100)) {
        return new Response(JSON.stringify({ error: 'cpu_percent must be between 0 and 100' }), {
          status: 400,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        });
      }
      if (memory_percent !== undefined && (memory_percent < 0 || memory_percent > 100)) {
        return new Response(JSON.stringify({ error: 'memory_percent must be between 0 and 100' }), {
          status: 400,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        });
      }
      if (disk_percent !== undefined && (disk_percent < 0 || disk_percent > 100)) {
        return new Response(JSON.stringify({ error: 'disk_percent must be between 0 and 100' }), {
          status: 400,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        });
      }
    }

    // 3. Check rate limit
    if (!checkRateLimit(payload.asset_id)) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded', retry_after: 60 }), {
        status: 429,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // 4. Initialize Supabase client with service role
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

    if (!supabaseUrl || !supabaseServiceKey) {
      console.error('Missing Supabase configuration');
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // 5. Verify API key using the same RPC as install-config
    const { data: validation, error: validationError } = await supabase
      .rpc('validate_asset_api_key', { p_api_key: apiKey });

    if (validationError) {
      console.error('API key validation error:', validationError.message);
      return new Response(JSON.stringify({ error: 'API key validation failed' }), {
        status: 401,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    const validationResult = Array.isArray(validation) ? validation[0] : validation;

    if (!validationResult || !validationResult.is_valid) {
      console.warn(`Invalid API key attempt for asset: ${payload.asset_id}`);
      return new Response(JSON.stringify({ error: 'Invalid API key or asset not found' }), {
        status: 401,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Verify the API key belongs to the asset in the payload
    if (validationResult.asset_id !== payload.asset_id) {
      console.warn(`API key asset mismatch: key belongs to ${validationResult.asset_id}, payload says ${payload.asset_id}`);
      return new Response(JSON.stringify({ error: 'API key does not match asset_id' }), {
        status: 401,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Get full asset data for status update (include DRA fields for ratchet)
    const { data: asset, error: assetError } = await supabase
      .from('monitored_assets')
      .select('id, tenant_id, criticality, ingestion_enabled, status, mcp_root_key, mcp_chain_key, mcp_dh_private_key, mcp_agent_dh_public_key')
      .eq('id', payload.asset_id)
      .single();

    if (assetError || !asset) {
      return new Response(JSON.stringify({ error: 'Asset not found' }), {
        status: 404,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // Check if ingestion is enabled
    if (!asset.ingestion_enabled) {
      return new Response(JSON.stringify({ error: 'Ingestion disabled for this asset' }), {
        status: 403,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // 6. Update asset status
    const now = new Date().toISOString();
    const previousStatus = asset.status;
    const newStatus = 'online';

    const updateData: Record<string, unknown> = {
      status: newStatus,
      last_heartbeat: now,
      agent_last_seen: now,
      agent_version: payload.agent_version || null,
      updated_at: now,
    };

    // Store latest metrics in health_check_result
    if (payload.metrics || payload.status) {
      updateData.health_check_result = {
        type: 'heartbeat',
        timestamp: now,
        metrics: payload.metrics || {},
        agent_status: payload.status || {},
      };
    }

    // Reset failure counter on successful heartbeat
    updateData.consecutive_failures = 0;

    const { error: updateError } = await supabase
      .from('monitored_assets')
      .update(updateData)
      .eq('id', asset.id);

    if (updateError) {
      console.error('Failed to update asset:', updateError);
      return new Response(JSON.stringify({ error: 'Failed to update asset status' }), {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    // 7. Log status change if occurred (for audit trail)
    if (previousStatus !== newStatus && previousStatus !== 'online') {
      console.log(`Asset ${asset.id} status changed: ${previousStatus} -> ${newStatus}`);

      // Optional: Insert into health history only on status change
      // This reduces DB writes significantly
      const { error: historyError } = await supabase
        .from('asset_health_history')
        .insert({
          asset_id: asset.id,
          tenant_id: asset.tenant_id,
          check_type: 'heartbeat',
          status: 'pass',
          details: {
            previous_status: previousStatus,
            new_status: newStatus,
            metrics: payload.metrics,
          },
        });
      if (historyError) {
        // Don't fail the heartbeat if history insert fails
        console.warn('Failed to insert health history:', historyError);
      }
    }

    // 8. DH Ratchet step (if agent sends dh_public_key and DRA is initialized)
    let responseDhPublicKey: string | undefined;
    if (payload.dh_public_key && asset.mcp_root_key && asset.mcp_chain_key && asset.mcp_dh_private_key) {
      const encryptionKey = Deno.env.get('ENCRYPTION_KEY');
      if (encryptionKey) {
        try {
          // Decrypt current DRA state
          const currentRootKey = await decryptString(asset.mcp_root_key, encryptionKey);
          const currentDhPrivKey = await decryptString(asset.mcp_dh_private_key, encryptionKey);

          if (currentRootKey && currentDhPrivKey) {
            // Compute new shared secret: X25519(platform_current_priv, agent_new_pub)
            const dhSharedSecret = computeSharedSecret(currentDhPrivKey, payload.dh_public_key);

            // Ratchet step: new root key + chain key from old root + new DH shared
            const draCtx = { assetId: asset.id, tenantId: asset.tenant_id };
            const ratcheted = await ratchetStep(currentRootKey, dhSharedSecret, draCtx);

            // Generate new platform ephemeral keypair
            const newPlatformKeypair = generateX25519Keypair();
            responseDhPublicKey = newPlatformKeypair.publicKey;

            // Derive new MCP token from the new chain key
            const newMcpToken = await deriveTokenFromChain(ratcheted.newChainKey, draCtx);

            // Store updated DRA state (encrypted)
            const draUpdate: Record<string, unknown> = {
              mcp_root_key: await encryptString(ratcheted.newRootKey, encryptionKey),
              mcp_chain_key: await encryptString(ratcheted.newChainKey, encryptionKey),
              mcp_dh_public_key: newPlatformKeypair.publicKey,
              mcp_dh_private_key: await encryptString(newPlatformKeypair.privateKey, encryptionKey),
              mcp_agent_dh_public_key: payload.dh_public_key,
              mcp_auth_token: await encryptString(newMcpToken, encryptionKey),
            };

            const { error: draUpdateError } = await supabase
              .from('monitored_assets')
              .update(draUpdate)
              .eq('id', asset.id);

            if (draUpdateError) {
              safeError('[Heartbeat] DRA ratchet DB update failed', draUpdateError);
            } else {
              safeLog(`[Heartbeat] DH ratchet step completed for asset ${asset.id}`);
            }
          }
        } catch (draError) {
          safeError('[Heartbeat] DH ratchet step failed', draError);
          // Non-fatal: heartbeat still succeeds, ratchet will retry next heartbeat
        }
      }
    }

    // 9. Calculate next heartbeat interval based on criticality
    const criticality = asset.criticality || 'medium';
    const nextHeartbeatIn = HEARTBEAT_INTERVALS[criticality] || 120;

    // 10. Build agent configuration
    const agentConfig = {
      log_endpoint: 'https://api.aisac.cisec.es/v1/logs',
      auth_method: 'api_key',
      log_batch_size: 100,
      log_flush_interval: 30,
      log_retention_hours: 24,
      features: {
        log_forwarding: asset.ingestion_enabled,
        metrics_collection: true,
      },
    };

    // 11. Return success response with config (+ DH public key if ratchet occurred)
    const responseBody: Record<string, unknown> = {
      success: true,
      next_heartbeat_in: nextHeartbeatIn,
      server_time: now,
      config: agentConfig,
    };

    if (responseDhPublicKey) {
      responseBody.dh_public_key = responseDhPublicKey;
    }

    return new Response(
      JSON.stringify(responseBody),
      { status: 200, headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('Heartbeat error:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
});
