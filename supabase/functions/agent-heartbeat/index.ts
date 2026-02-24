import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-requested-with, x-api-key',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE',
  'Access-Control-Max-Age': '86400',
};

function getCorsHeaders(_req: Request): Record<string, string> {
  return corsHeaders;
}

function handleCorsPreflight(_req: Request): Response {
  return new Response(null, { status: 204, headers: corsHeaders });
}

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

    // Validate API key format: ak_<64 hex chars> or aisac_<48 hex chars>
    const validAkFormat = apiKey.startsWith('ak_') && /^ak_[0-9a-f]{63}$/.test(apiKey);
    const validAisacFormat = apiKey.startsWith('aisac_') && /^aisac_[0-9a-f]{48}$/.test(apiKey);
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
        headers: { ...gFailed to insertetCorsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // 5. Verify API key and get asset
    // Compare API key directly (keys stored as ak_<64 hex> or aisac_<48 hex>)
    const { data: asset, error: assetError } = await supabase
      .from('monitored_assets')
      .select('id, tenant_id, criticality, ingestion_enabled, status')
      .eq('id', payload.asset_id)
      .eq('api_key', apiKey)
      .single();

    if (assetError || !asset) {
      // Log failed attempt for security audit
      console.warn(`Invalid API key attempt for asset: ${payload.asset_id}`, assetError?.message);
      return new Response(JSON.stringify({ error: 'Invalid API key or asset not found' }), {
        status: 401,
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

    // 8. Calculate next heartbeat interval based on criticality
    const criticality = asset.criticality || 'medium';
    const nextHeartbeatIn = HEARTBEAT_INTERVALS[criticality] || 120;

    // 9. Build agent configuration
    // The agent uses this config to know where to send logs and how often
    // Usamos el proxy de CISEC para proteger el endpoint de Supabase
    const agentConfig = {
      // Endpoint para enviar logs - proxy CISEC que reenvía a syslog-ingest
      log_endpoint: 'https://api.aisac.cisec.es/v1/logs',
      // El agente debe usar X-API-Key para autenticar
      auth_method: 'api_key', // Agent debe enviar X-API-Key header
      log_batch_size: 100, // Max logs per batch
      log_flush_interval: 30, // Seconds between log flushes
      log_retention_hours: 24, // Keep logs locally if can't send
      features: {
        log_forwarding: asset.ingestion_enabled,
        metrics_collection: true,
      },
    };

    // 10. Return success response with config
    return new Response(
      JSON.stringify({
        success: true,
        next_heartbeat_in: nextHeartbeatIn,
        server_time: now,
        config: agentConfig,
      }),
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
