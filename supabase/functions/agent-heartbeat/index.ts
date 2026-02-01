// AISAC Agent Heartbeat Edge Function
// Receives heartbeat from agents, validates API Key, updates asset status
//
// IMPORTANT: API Key is stored in monitored_assets.api_key (NOT a separate api_keys table)
//
// Expected headers:
//   X-API-Key: aisac_xxxxxxxxxxxx
//
// Expected body:
//   {
//     "asset_id": "uuid",
//     "timestamp": "ISO8601",
//     "agent_version": "1.0.0",
//     "metrics": {
//       "cpu_percent": 25.5,
//       "memory_percent": 60.2,
//       "disk_percent": 45.0,
//       "uptime_seconds": 3600
//     }
//   }

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-api-key, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

interface HeartbeatPayload {
  asset_id: string;
  timestamp: string;
  agent_version: string;
  metrics: {
    cpu_percent: number;
    memory_percent: number;
    disk_percent: number;
    uptime_seconds: number;
  };
}

interface HeartbeatResponse {
  success: boolean;
  next_heartbeat_in?: number;
  message?: string;
}

serve(async (req: Request) => {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // Only allow POST
  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ success: false, message: "Method not allowed" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    // Get API Key from header
    const apiKey = req.headers.get("X-API-Key") || req.headers.get("x-api-key");

    if (!apiKey) {
      return new Response(
        JSON.stringify({ success: false, message: "Missing API Key" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Validate API Key format (aisac_ + 48 hex chars = 54 total)
    if (!apiKey.startsWith("aisac_") || apiKey.length !== 54) {
      return new Response(
        JSON.stringify({ success: false, message: "Invalid API Key format" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Parse body
    const payload: HeartbeatPayload = await req.json();

    if (!payload.asset_id) {
      return new Response(
        JSON.stringify({ success: false, message: "Missing asset_id" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Initialize Supabase client with service role key
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !supabaseServiceKey) {
      console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
      return new Response(
        JSON.stringify({ success: false, message: "Server configuration error" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Validate API Key against monitored_assets table
    // The API Key is stored directly in monitored_assets.api_key
    const { data: asset, error: assetError } = await supabase
      .from("monitored_assets")
      .select("id, tenant_id, name, criticality, ingestion_enabled, status")
      .eq("id", payload.asset_id)
      .eq("api_key", apiKey)
      .single();

    if (assetError || !asset) {
      console.error("API Key validation failed:", assetError?.message || "Asset not found or API Key mismatch");
      return new Response(
        JSON.stringify({ success: false, message: "Invalid API Key or asset not found" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Check if asset is enabled for ingestion
    if (!asset.ingestion_enabled) {
      return new Response(
        JSON.stringify({ success: false, message: "Asset ingestion is disabled" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Check if asset is not decommissioned
    if (asset.status === "decommissioned") {
      return new Response(
        JSON.stringify({ success: false, message: "Asset is decommissioned" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Update the monitored asset's last_seen and status
    const { error: updateError } = await supabase
      .from("monitored_assets")
      .update({
        status: "online",
        last_seen_at: new Date().toISOString(),
        agent_version: payload.agent_version,
        metrics: payload.metrics,
      })
      .eq("id", payload.asset_id);

    if (updateError) {
      console.error("Failed to update asset:", updateError.message);
      return new Response(
        JSON.stringify({ success: false, message: "Failed to update asset status" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Get the configured heartbeat interval for this tenant (default 120 seconds)
    let nextHeartbeatIn = 120;

    const { data: tenantConfig } = await supabase
      .from("tenant_settings")
      .select("heartbeat_interval")
      .eq("tenant_id", asset.tenant_id)
      .single();

    if (tenantConfig?.heartbeat_interval) {
      nextHeartbeatIn = tenantConfig.heartbeat_interval;
    }

    const response: HeartbeatResponse = {
      success: true,
      next_heartbeat_in: nextHeartbeatIn,
      message: "Heartbeat received",
    };

    console.log(`Heartbeat received from asset ${asset.name} (${payload.asset_id})`);

    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Heartbeat error:", error);
    return new Response(
      JSON.stringify({ success: false, message: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
