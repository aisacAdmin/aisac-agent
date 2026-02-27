// AISAC Install Config Edge Function
// Called by the install script to get tenant config before installing the agent.
//
// The client only needs to provide their asset API key. The function returns
// everything the install script needs: tenant_id, Wazuh Manager config, and
// AISAC Agent config.
//
// Expected headers:
//   X-API-Key: aisac_xxxxxxxxxxxx
//
// GET Response:
//   {
//     "tenant_id": "uuid",
//     "asset_id": "uuid",
//     "asset_name": "string",
//     "wazuh": {
//       "manager_ip": "x.x.x.x",
//       "manager_port": 1514,
//       "agent_group": "tenant-uuid"
//     },
//     "aisac": {
//       "heartbeat_url": "https://...",
//       "ingest_url": "https://...",
//       "api_key": "aisac_xxx"
//     }
//   }
//
// PATCH - Update integration_config after Wazuh agent installation
// Headers:
//   X-API-Key: aisac_xxxxxxxxxxxx
// Body:
//   {
//     "integration_type": "wazuh",
//     "integration_config": {
//       "wazuh_agent_name": "wazuh-aisac-staging-linux",
//       "wazuh_agent_id": "002"
//     }
//   }

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-api-key, content-type",
  "Access-Control-Allow-Methods": "GET, PATCH, OPTIONS",
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

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (req.method !== "GET" && req.method !== "PATCH") {
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

    // ─── PATCH: Update integration_config after Wazuh agent installation ───
    if (req.method === "PATCH") {
      const body = await req.json();
      const { integration_type, integration_config } = body;

      if (!integration_type || !integration_config) {
        return new Response(
          JSON.stringify({ error: "Missing integration_type or integration_config" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const { error: updateError } = await supabase
        .from("monitored_assets")
        .update({
          integration_type,
          integration_config,
        })
        .eq("id", asset_id)
        .eq("tenant_id", tenant_id);

      if (updateError) {
        console.error("Failed to update integration_config:", updateError.message);
        return new Response(
          JSON.stringify({ error: "Failed to update integration config" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      console.log(`Updated integration_config for asset ${asset_id}: ${JSON.stringify(integration_config)}`);

      return new Response(
        JSON.stringify({ success: true, asset_id, integration_type, integration_config }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ─── GET: Return full config for the install script ───

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
    // Use AISAC_AUTH_TOKEN (legacy JWT anon key) for agent auth.
    // SUPABASE_ANON_KEY may return the new publishable key format (sb_publishable_...)
    // which is not accepted by Edge Functions gateway as Authorization Bearer token.
    const authToken = Deno.env.get("AISAC_AUTH_TOKEN") || Deno.env.get("SUPABASE_ANON_KEY") || "";

    // 6. Return full config for the install script
    return new Response(
      JSON.stringify({
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
          auth_token: authToken,
        },
      }),
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
