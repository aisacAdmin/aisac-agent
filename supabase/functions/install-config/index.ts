// AISAC Install Config Edge Function
// Called by the install script to get tenant config before installing the agent.
//
// The client only needs to provide their asset API key. The function returns
// everything the install script needs: tenant_id, Wazuh Manager config,
// AISAC Agent config, and optionally a Cloudflare Tunnel token for MCP.
//
// Expected headers:
//   X-API-Key: aisac_xxxxxxxxxxxx
//
// Query params (optional):
//   ?mcp=true  — Request Cloudflare Tunnel provisioning for MCP Server
//
// Response:
//   {
//     "tenant_id": "uuid",
//     "asset_id": "uuid",
//     "asset_name": "string",
//     "wazuh": { ... },
//     "aisac": { ... },
//     "tunnel": {                          // only if ?mcp=true
//       "token": "<cloudflared-token>",
//       "hostname": "mcp-slug-uuid.aisac.tech"
//     }
//   }

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { encryptString, decryptString } from "../_shared/crypto-utils.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-api-key, content-type",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

function extractApiKey(req: Request): string | null {
  const xApiKey = req.headers.get("X-API-Key") || req.headers.get("x-api-key");
  if (xApiKey) return xApiKey;

  const authHeader = req.headers.get("Authorization") || req.headers.get("authorization");
  if (authHeader?.startsWith("Bearer ")) return authHeader.substring(7);

  return null;
}

function isValidApiKey(apiKey: string): boolean {
  const validAk = apiKey.startsWith("ak_") && /^ak_[0-9a-f]{63}$/.test(apiKey);
  const validAisac = apiKey.startsWith("aisac_") && apiKey.length === 54;
  return validAk || validAisac;
}

/**
 * Slugify asset name for use as subdomain component.
 * Lowercase, replace spaces/underscores with hyphens, strip non-alphanumeric, max 30 chars.
 */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[\s_]+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 30);
}

// ============================================================================
// Cloudflare Tunnel Provisioning
// ============================================================================

interface TunnelResult {
  tunnelId: string;
  token: string;
  hostname: string;
}

/**
 * Provision a Cloudflare Tunnel for an asset's MCP Server.
 * Creates the tunnel, configures the public hostname route, and creates a DNS CNAME.
 */
async function provisionTunnel(
  assetId: string,
  assetName: string,
  cfAccountId: string,
  cfApiToken: string,
  cfZoneId: string,
): Promise<TunnelResult> {
  const slug = slugify(assetName);
  const hostname = `mcp-${slug}-${assetId.split("-")[0]}.aisac.tech`;
  const tunnelName = `mcp-${slug}-${assetId.split("-")[0]}`;

  // 1. Generate a random tunnel secret (32 bytes, base64)
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const tunnelSecret = btoa(String.fromCharCode(...secretBytes));

  // 2. Create the tunnel
  const createRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/cfd_tunnel`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${cfApiToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: tunnelName,
        tunnel_secret: tunnelSecret,
      }),
    }
  );

  const createData = await createRes.json();
  let tunnelId: string;

  if (!createData.success) {
    // If tunnel already exists, find it by name
    const errMsg = createData.errors?.[0]?.message || "";
    if (errMsg.includes("already have a tunnel with this name")) {
      console.log("[tunnel] Tunnel already exists, looking up by name:", tunnelName);
      const listRes = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/cfd_tunnel?name=${encodeURIComponent(tunnelName)}&is_deleted=false`,
        { headers: { Authorization: `Bearer ${cfApiToken}` } }
      );
      const listData = await listRes.json();
      if (!listData.success || !listData.result?.length) {
        throw new Error(`Tunnel exists but could not be found by name: ${tunnelName}`);
      }
      tunnelId = listData.result[0].id;
      console.log("[tunnel] Found existing tunnel:", tunnelId);
    } else {
      throw new Error(`Failed to create tunnel: ${errMsg || JSON.stringify(createData.errors)}`);
    }
  } else {
    tunnelId = createData.result.id;
    console.log("[tunnel] Tunnel created:", tunnelId);
  }

  // 3. Configure the tunnel's public hostname (ingress rule)
  const configRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/cfd_tunnel/${tunnelId}/configurations`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${cfApiToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        config: {
          ingress: [
            {
              hostname: hostname,
              service: "http://localhost:3000",
            },
            {
              // Catch-all rule (required by Cloudflare)
              service: "http_status:404",
            },
          ],
        },
      }),
    }
  );

  const configData = await configRes.json();
  if (!configData.success) {
    const errMsg = configData.errors?.[0]?.message || "Unknown error";
    throw new Error(`Failed to configure tunnel ingress: ${errMsg}`);
  }

  // 4. Create DNS CNAME record
  const dnsRes = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/dns_records`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${cfApiToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "CNAME",
        name: `mcp-${slug}-${assetId.split("-")[0]}`,
        content: `${tunnelId}.cfargotunnel.com`,
        proxied: true,
      }),
    }
  );

  const dnsData = await dnsRes.json();
  if (!dnsData.success) {
    // If CNAME already exists (reinstall scenario), that's OK
    const errCode = dnsData.errors?.[0]?.code;
    if (errCode !== 81057) { // 81057 = record already exists
      const errMsg = dnsData.errors?.[0]?.message || "Unknown error";
      throw new Error(`Failed to create DNS record: ${errMsg}`);
    }
  }

  // 5. Get the tunnel connector token
  const tokenRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/cfd_tunnel/${tunnelId}/token`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${cfApiToken}`,
      },
    }
  );

  const tokenData = await tokenRes.json();
  if (!tokenData.success) {
    const errMsg = tokenData.errors?.[0]?.message || "Unknown error";
    throw new Error(`Failed to get tunnel token: ${errMsg}`);
  }

  return {
    tunnelId,
    token: tokenData.result,
    hostname,
  };
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (req.method !== "GET") {
    return new Response(
      JSON.stringify({ error: "Method not allowed" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    // 1. Extract and validate API key
    const apiKey = extractApiKey(req);
    if (!apiKey) {
      return new Response(
        JSON.stringify({ error: "Missing X-API-Key header" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!isValidApiKey(apiKey)) {
      return new Response(
        JSON.stringify({ error: "Invalid API key format" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 2. Initialize Supabase client
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !supabaseServiceKey) {
      console.error("Missing Supabase configuration");
      return new Response(
        JSON.stringify({ error: "Server configuration error" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // 3. Validate API key and get asset info
    const { data: validation, error: validationError } = await supabase
      .rpc("validate_asset_api_key", { p_api_key: apiKey });

    if (validationError) {
      console.error("API key validation error:", validationError.message);
      return new Response(
        JSON.stringify({ error: "API key validation failed" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // RPC may return an array (SETOF) or a single object depending on the definition
    const validationResult = Array.isArray(validation) ? validation[0] : validation;

    if (!validationResult || !validationResult.is_valid) {
      return new Response(
        JSON.stringify({ error: "Invalid API key or asset not found" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { asset_id, tenant_id, asset_name } = validationResult;

    // 4. Get Wazuh Manager config from environment
    const wazuhManagerIp = Deno.env.get("WAZUH_MANAGER_IP");
    const wazuhManagerPort = parseInt(Deno.env.get("WAZUH_MANAGER_PORT") || "1514");

    if (!wazuhManagerIp) {
      console.error("Missing WAZUH_MANAGER_IP environment variable");
      return new Response(
        JSON.stringify({ error: "Wazuh Manager not configured" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 5. Get AISAC platform URLs and anon key from environment
    const heartbeatUrl = Deno.env.get("AISAC_HEARTBEAT_URL") || `${supabaseUrl}/functions/v1/agent-heartbeat`;
    const ingestUrl = Deno.env.get("AISAC_INGEST_URL") || `${supabaseUrl}/functions/v1/syslog-ingest`;
    const supabaseAnonKey = Deno.env.get("AISAC_ANON_JWT") || Deno.env.get("SUPABASE_ANON_KEY") || "";

    // 6. Check if MCP tunnel is requested
    const url = new URL(req.url);
    const mcpRequested = url.searchParams.get("mcp") === "true";
    let tunnelData: { token: string; hostname: string } | null = null;

    if (mcpRequested) {
      const cfAccountId = Deno.env.get("CF_ACCOUNT_ID");
      const cfApiToken = Deno.env.get("CF_API_TOKEN");
      const cfZoneId = Deno.env.get("CF_ZONE_ID");
      const encryptionKey = Deno.env.get("ENCRYPTION_KEY");

      console.log("[install-config] CF env check:", { cfAccountId: !!cfAccountId, cfApiToken: !!cfApiToken, cfZoneId: !!cfZoneId, encryptionKey: !!encryptionKey });
      if (cfAccountId && cfApiToken && cfZoneId && encryptionKey) {
        // Check if tunnel already exists for this asset
        const { data: asset } = await supabase
          .from("monitored_assets")
          .select("cf_tunnel_id, cf_tunnel_token, cf_tunnel_hostname")
          .eq("id", asset_id)
          .single();

        if (asset?.cf_tunnel_token && asset?.cf_tunnel_hostname) {
          // Tunnel already provisioned — return existing token
          try {
            const decryptedToken = await decryptString(asset.cf_tunnel_token, encryptionKey);
            tunnelData = {
              token: decryptedToken,
              hostname: asset.cf_tunnel_hostname,
            };
            console.log(`[install-config] Returning existing tunnel for asset ${asset_id}`);
          } catch {
            console.error("[install-config] Failed to decrypt existing tunnel token, re-provisioning");
          }
        }

        if (!tunnelData) {
          // Provision new tunnel
          try {
            const result = await provisionTunnel(
              asset_id,
              asset_name,
              cfAccountId,
              cfApiToken,
              cfZoneId,
            );

            // Store tunnel info in DB (token encrypted)
            const encryptedToken = await encryptString(result.token, encryptionKey);

            await supabase
              .from("monitored_assets")
              .update({
                cf_tunnel_id: result.tunnelId,
                cf_tunnel_token: encryptedToken,
                cf_tunnel_hostname: result.hostname,
              })
              .eq("id", asset_id);

            tunnelData = result;
            console.log(`[install-config] Provisioned new tunnel: ${result.hostname}`);
          } catch (err) {
            console.error("[install-config] Tunnel provisioning failed:", String(err));
            // Non-fatal — installer falls back to direct IP
          }
        }
      } else {
        console.log("[install-config] MCP requested but Cloudflare env vars not configured");
      }
    }

    // 7. Return full config for the install script
    const response: Record<string, unknown> = {
      tenant_id,
      asset_id,
      asset_name,
      wazuh: {
        manager_ip: wazuhManagerIp,
        manager_port: wazuhManagerPort,
        agent_group: tenant_id,
      },
      aisac: {
        heartbeat_url: heartbeatUrl,
        ingest_url: ingestUrl,
        api_key: apiKey,
        auth_token: supabaseAnonKey,
      },
    };

    if (tunnelData) {
      response.tunnel = {
        token: tunnelData.token,
        hostname: tunnelData.hostname,
      };
    }


    return new Response(
      JSON.stringify(response),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("Install config error:", error);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
