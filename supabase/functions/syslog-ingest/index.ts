// AISAC Syslog Ingest Edge Function
// Receives batched log events from agents and stores them in the database
//
// IMPORTANT: API Key is stored in monitored_assets.api_key (NOT a separate api_keys table)
// Uses validate_asset_api_key RPC function for validation
//
// Expected headers:
//   X-API-Key: aisac_xxxxxxxxxxxx
//   OR
//   Authorization: Bearer aisac_xxxxxxxxxxxx
//
// Expected body:
//   {
//     "events": [
//       {
//         "@timestamp": "ISO8601",
//         "source": "suricata",
//         "host": "hostname",
//         "message": "raw message",
//         "fields": { ... parsed fields ... }
//       }
//     ]
//   }

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-api-key, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

interface LogEvent {
  "@timestamp": string;
  source: string;
  tenant_id?: string;
  host: string;
  message?: string;
  fields?: Record<string, unknown>;
}

interface IngestPayload {
  events: LogEvent[];
}

interface IngestResponse {
  success: boolean;
  received?: number;
  stored?: number;
  message?: string;
}

// Extract API Key from various header formats
function extractApiKey(req: Request): string | null {
  // Try X-API-Key header first
  const xApiKey = req.headers.get("X-API-Key") || req.headers.get("x-api-key");
  if (xApiKey) {
    return xApiKey;
  }

  // Try Authorization: Bearer header
  const authHeader = req.headers.get("Authorization") || req.headers.get("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  return null;
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
    const apiKey = extractApiKey(req);

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
    const payload: IngestPayload = await req.json();

    if (!payload.events || !Array.isArray(payload.events)) {
      return new Response(
        JSON.stringify({ success: false, message: "Missing or invalid events array" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (payload.events.length === 0) {
      return new Response(
        JSON.stringify({ success: true, received: 0, stored: 0, message: "No events to process" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
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

    // Validate API Key using the RPC function
    const { data: validation, error: validationError } = await supabase
      .rpc("validate_asset_api_key", { p_api_key: apiKey });

    if (validationError) {
      console.error("API Key validation error:", validationError.message);
      return new Response(
        JSON.stringify({ success: false, message: "API Key validation failed" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!validation || !validation.is_valid) {
      console.error("Invalid API Key");
      return new Response(
        JSON.stringify({ success: false, message: "Invalid API Key" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { asset_id, tenant_id, asset_name } = validation;

    // Prepare events for insertion with tenant_id and asset_id
    const eventsToInsert = payload.events.map((event) => ({
      tenant_id: tenant_id,
      monitored_asset_id: asset_id,
      timestamp: event["@timestamp"] || new Date().toISOString(),
      source: event.source || "unknown",
      host: event.host || "unknown",
      message: event.message || null,
      fields: event.fields || {},
      raw_event: event, // Store the complete original event
    }));

    // Batch insert events into syslog_events table (or log_events depending on schema)
    const { data: insertedData, error: insertError } = await supabase
      .from("log_events")
      .insert(eventsToInsert)
      .select("id");

    if (insertError) {
      console.error("Failed to insert events:", insertError.message);

      // Try syslog_events table as fallback
      const { data: fallbackData, error: fallbackError } = await supabase
        .from("syslog_events")
        .insert(eventsToInsert)
        .select("id");

      if (fallbackError) {
        // If both tables fail, still acknowledge receipt to prevent agent retry loop
        console.error("Fallback table also failed:", fallbackError.message);

        // Check if it's a schema error (table doesn't exist)
        if (fallbackError.code === "42P01" || fallbackError.code === "42703") {
          console.error("Neither log_events nor syslog_events table exists");
          return new Response(
            JSON.stringify({
              success: true,
              received: payload.events.length,
              stored: 0,
              message: "Events received but storage unavailable"
            }),
            { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        return new Response(
          JSON.stringify({ success: false, message: "Failed to store events" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      // Fallback succeeded
      const storedCount = fallbackData?.length || 0;
      console.log(`Stored ${storedCount} events from ${asset_name} (${asset_id}) in syslog_events`);

      return new Response(
        JSON.stringify({
          success: true,
          received: payload.events.length,
          stored: storedCount,
          message: `Successfully stored ${storedCount} events`
        }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const storedCount = insertedData?.length || 0;

    // Optionally update last log received timestamp on the asset
    await supabase
      .from("monitored_assets")
      .update({
        last_log_at: new Date().toISOString(),
        status: "online",
      })
      .eq("id", asset_id);

    console.log(`Stored ${storedCount} events from ${asset_name} (${asset_id})`);

    const response: IngestResponse = {
      success: true,
      received: payload.events.length,
      stored: storedCount,
      message: `Successfully stored ${storedCount} events`,
    };

    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Ingest error:", error);
    return new Response(
      JSON.stringify({ success: false, message: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
