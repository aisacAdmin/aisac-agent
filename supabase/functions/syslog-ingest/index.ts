/**
 * Syslog Ingestion Edge Function
 *
 * Receives security alerts via Syslog/Rsyslog forwarding and ingests them into AISAC platform.
 * Supports both JSON batch format and raw syslog format (RFC 3164 and RFC 5424).
 *
 * **IMPORTANT: Multi-Tenant & Multi-Asset Isolation**
 *
 * Both `tenant_id` and `asset_id` are REQUIRED for all ingestion requests.
 * This ensures proper data isolation for multi-tenant and multi-asset environments.
 * Configure these values in the AISAC Agent during installation.
 *
 * **Authentication Methods:**
 *
 * 1. **API Key (Recommended for Agents):** Uses X-API-Key header with aisac_xxx format.
 *    The tenant_id and asset_id are automatically derived from the linked asset.
 *
 * 2. **JWT:** Requires tenant_id AND asset_id in request body/query params.
 *
 * **API Specification:**
 *
 * POST /functions/v1/syslog-ingest
 * Authorization: Bearer <api_key> OR X-API-Key: <aisac_api_key>
 * Content-Type: application/json OR text/plain
 *
 * Request Body (Option 1 - JSON Batch with JWT):
 * {
 *   "tenant_id": "uuid",
 *   "asset_id": "uuid",     // REQUIRED - configure during agent installation
 *   "source": "rsyslog",
 *   "messages": [
 *     "Oct 17 10:30:00 firewall1 %ASA-4-106023: Deny tcp src inside:10.1.1.1/12345 dst outside:192.0.2.1/80",
 *     "Oct 17 10:30:01 firewall1 %ASA-4-106023: Deny tcp src inside:10.1.1.2/12346 dst outside:192.0.2.1/443"
 *   ]
 * }
 *
 * Request Body (Option 2 - Raw Syslog with JWT):
 * URL: /functions/v1/syslog-ingest?tenant_id=<uuid>&asset_id=<uuid>
 * Body: Oct 17 10:30:00 firewall1 %ASA-4-106023: Deny tcp src inside:10.1.1.1/12345 dst outside:192.0.2.1/80
 *
 * Response 200:
 * {
 *   "status": "success",
 *   "processed": 2,
 *   "failed": 0,
 *   "alert_ids": ["uuid1", "uuid2"],
 *   "rate_limit_remaining": 498,
 *   "errors": [] // Only present if failed > 0
 * }
 *
 * Response 400:
 * {
 *   "error": "Validación de datos fallida",
 *   "details": "El cuerpo de solicitud no es válido"
 * }
 *
 * Response 429:
 * {
 *   "error": "Límite de tasa excedido",
 *   "details": "Ha superado el límite de 500 mensajes por minuto",
 *   "retry_after_seconds": 60
 * }
 *
 * **Testing Examples:**
 *
 * ```bash
 * # Test 1: API Key auth (recommended - tenant/asset derived from key)
 * curl -X POST https://your-project.supabase.co/functions/v1/syslog-ingest \
 *   -H "X-API-Key: aisac_your_api_key_here" \
 *   -H "Content-Type: text/plain" \
 *   -d '<134>Oct 17 10:30:00 firewall1 %ASA-4-106023: Deny tcp src inside:10.1.1.1/12345 dst outside:192.0.2.1/80'
 *
 * # Test 2: JWT auth - Batch JSON format (requires tenant_id AND asset_id)
 * curl -X POST https://your-project.supabase.co/functions/v1/syslog-ingest \
 *   -H "Authorization: Bearer YOUR_JWT_TOKEN" \
 *   -H "Content-Type: application/json" \
 *   -d '{
 *     "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
 *     "asset_id": "987fcdeb-51a2-43d8-b012-789456123abc",
 *     "source": "rsyslog",
 *     "messages": [
 *       "<134>Oct 17 10:30:00 firewall1 %ASA-4-106023: Deny tcp src inside:10.1.1.1/12345 dst outside:192.0.2.1/80",
 *       "<38>Oct 17 10:31:00 server sshd[1234]: Failed password for admin from 10.0.0.50 port 22 ssh2"
 *     ]
 *   }'
 *
 * # Test 3: JWT auth - Raw syslog format (requires tenant_id AND asset_id in query params)
 * curl -X POST "https://your-project.supabase.co/functions/v1/syslog-ingest?tenant_id=123e4567-e89b-12d3-a456-426614174000&asset_id=987fcdeb-51a2-43d8-b012-789456123abc" \
 *   -H "Authorization: Bearer YOUR_JWT_TOKEN" \
 *   -H "Content-Type: text/plain" \
 *   -d '<134>Oct 17 10:30:00 firewall1 %ASA-4-106023: Deny tcp src inside:10.1.1.1/12345 dst outside:192.0.2.1/80'
 *
 * # Test 4: RFC 5424 format with API Key
 * curl -X POST https://your-project.supabase.co/functions/v1/syslog-ingest \
 *   -H "X-API-Key: aisac_your_api_key_here" \
 *   -H "Content-Type: text/plain" \
 *   -d '<134>1 2025-10-17T10:30:00Z firewall1 firewall - - - Deny tcp src 10.1.1.1 dst 192.0.2.1'
 * ```
 *
 * **Rsyslog Configuration Example:**
 *
 * Create `/etc/rsyslog.d/aisac.conf` on the client machine:
 *
 * ```bash
 * # AISAC Syslog Forwarding Configuration
 *
 * # Option 1: JSON Batch Format (recommended for high volume)
 * template(name="AisacJSON" type="list") {
 *     constant(value="{\"tenant_id\":\"YOUR_TENANT_ID\",")
 *     constant(value="\"source\":\"rsyslog\",")
 *     constant(value="\"messages\":[\"")
 *     property(name="msg" format="json")
 *     constant(value="\"]}")
 * }
 *
 * *.* action(
 *     type="omhttp"
 *     server="YOUR_SUPABASE_PROJECT.supabase.co"
 *     serverport="443"
 *     restpath="/functions/v1/syslog-ingest"
 *     template="AisacJSON"
 *     httpheaders=["Authorization: Bearer YOUR_API_KEY", "Content-Type: application/json"]
 * )
 *
 * # Option 2: Raw Syslog Format (simple but lower performance)
 * *.* action(
 *     type="omhttp"
 *     server="YOUR_SUPABASE_PROJECT.supabase.co"
 *     serverport="443"
 *     restpath="/functions/v1/syslog-ingest"
 *     httpheaders=["Authorization: Bearer YOUR_API_KEY", "Content-Type: text/plain"]
 * )
 *
 * # Option 3: Filter by severity (critical/high only)
 * *.crit;*.alert;*.emerg action(
 *     type="omhttp"
 *     server="YOUR_SUPABASE_PROJECT.supabase.co"
 *     serverport="443"
 *     restpath="/functions/v1/syslog-ingest"
 *     template="AisacJSON"
 *     httpheaders=["Authorization: Bearer YOUR_API_KEY", "Content-Type: application/json"]
 * )
 * ```
 *
 * **Error Scenarios:**
 * - 401: Missing or invalid authentication token
 * - 403: Tenant access denied
 * - 400: Invalid request format
 * - 429: Rate limit exceeded (>500 messages/min per tenant)
 * - 500: Internal server error
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { z } from 'https://deno.land/x/zod@v3.22.4/mod.ts';
import { authenticateRequest, createAuthErrorResponse } from '../_shared/auth-middleware.ts';
import { getCorsHeaders } from '../_shared/cors.ts';
import { validateSupabaseEnv } from '../_shared/envValidation.ts';
import { safeLog, safeError } from '../_shared/logSanitization.ts';

// ============================================================================
// Suricata Telemetry Filter (MUST be filtered at ingestion time)
// These event types are protocol metadata, NOT security alerts.
// Keeping them out of the pipeline reduces noise and storage costs.
// ============================================================================
const SURICATA_TELEMETRY_EVENT_TYPES = new Set([
  'dns', // DNS queries/responses - network metadata
  'tls', // TLS handshakes - connection metadata
  'flow', // Flow records - traffic statistics
  'http', // HTTP transactions - web traffic metadata
  'stats', // Suricata engine statistics - not security-relevant
  'fileinfo', // File transfer metadata
  'smb', // SMB protocol metadata
  'krb5', // Kerberos metadata
  'dhcp', // DHCP transactions
  'ntp', // NTP metadata
  'snmp', // SNMP metadata
  'sip', // SIP protocol metadata
  'rfb', // VNC/RFB metadata
  'mqtt', // MQTT protocol metadata
  'ftp', // FTP metadata
  'tftp', // TFTP metadata
  'ikev2', // IKEv2 VPN metadata
  'nfs', // NFS metadata
  'ssh', // SSH metadata (not alerts)
]);

// ============================================================================
// Types and Validation Schemas
// ============================================================================

/**
 * Parsed syslog message structure
 */
interface ParsedSyslog {
  priority?: number;
  facility?: number;
  severity?: number;
  timestamp?: string;
  hostname?: string;
  tag?: string;
  message: string;
  raw: string;
  source?: string;
}

/**
 * Syslog batch request schema (JSON format) - For JWT auth
 * REQUIRED: Both tenant_id and asset_id must be provided for multi-tenant/multi-asset isolation.
 * The agent should be configured with these values during installation.
 */
const SyslogBatchSchema = z.object({
  tenant_id: z.string().uuid('tenant_id debe ser un UUID válido'),
  asset_id: z.string().uuid('asset_id debe ser un UUID válido'),
  source: z.string().optional().default('rsyslog'),
  messages: z.array(z.string()).min(1).max(100), // Max 100 messages per batch
});

/**
 * Syslog batch request schema for API Key auth (tenant_id obtained from asset)
 */
const SyslogApiKeyBatchSchema = z.object({
  source: z.string().optional().default('rsyslog'),
  messages: z.array(z.string()).min(1).max(100), // Max 100 messages per batch
});

/**
 * Alert severity levels
 */
type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Alert types
 */
type AlertType =
  | 'network_intrusion'
  | 'malware'
  | 'phishing'
  | 'unauthorized_access'
  | 'data_exfiltration'
  | 'brute_force'
  | 'ddos'
  | 'vulnerability_exploit'
  | 'policy_violation'
  | 'anomaly'
  | 'other';

/**
 * Normalized alert structure (matching alert-ingest format)
 */
interface NormalizedAlert {
  source: string;
  severity: SeverityLevel;
  type: AlertType;
  title: string;
  description: string;
  timestamp: string;
  entities: {
    ips?: string[];
    domains?: string[];
    hashes?: string[];
    users?: string[];
    ports?: number[];
  };
  protocol?: string | null;
  // Explicit port fields for accurate OpenSearch indexing
  src_port?: number | null;
  dest_port?: number | null;
  // Explicit IP fields for Suricata events (ensures aggregations work even when src==dest)
  src_ip?: string | null;
  dest_ip?: string | null;
  raw_data: unknown;
  // Wazuh agent routing: when alerts come from a collector, these fields
  // identify the real origin agent so we can resolve the correct asset_id
  wazuh_agent_name?: string;
  wazuh_agent_id?: string;
  wazuh_agent_ip?: string;
}

// ============================================================================
// Rate Limiting (500 messages/min - higher than API ingestion)
// ============================================================================

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

/**
 * Check rate limit for tenant (500 messages per minute for syslog)
 */
function checkRateLimit(
  tenantId: string,
  messageCount: number = 1
): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const key = tenantId;
  const limit = 500; // Higher limit for syslog (batch operations)
  const windowMs = 60000; // 1 minute

  let bucket = rateLimitStore.get(key);

  // Reset if window expired
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateLimitStore.set(key, bucket);
  }

  // Increment counter
  bucket.count += messageCount;

  const remaining = Math.max(0, limit - bucket.count);
  const allowed = bucket.count <= limit;

  return { allowed, remaining };
}

// ============================================================================
// API Key Authentication for AISAC Agents
// ============================================================================

/**
 * SIEM Configuration from asset (matches inventory.ts types)
 */
interface SIEMConfig {
  enabled: boolean;
  monitoring?: {
    log_collection?: boolean;
    event_sources?: string[];
    log_level?: 'debug' | 'info' | 'warning' | 'error' | 'critical';
    min_severity?: 'low' | 'medium' | 'high' | 'critical';
  };
  alerting?: {
    enabled?: boolean;
    severity_threshold?: 'low' | 'medium' | 'high' | 'critical';
    alert_channels?: string[];
  };
  correlation?: {
    enabled?: boolean;
    rule_ids?: string[];
  };
  retention?: {
    days?: number;
    archive?: boolean;
  };
  baseline?: {
    enabled?: boolean;
    anomaly_detection?: boolean;
  };
  // Note: PostgreSQL storage (external_alerts) has been removed.
  // All SIEM events are stored exclusively in OpenSearch.
}

/**
 * Result of API Key validation
 */
interface ApiKeyValidationResult {
  valid: boolean;
  tenantId?: string;
  assetId?: string;
  assetName?: string;
  siemEnabled?: boolean; // Whether SIEM is enabled for this asset
  siemConfig?: SIEMConfig; // Full SIEM configuration for behavior control
  error?: string;
}

/**
 * Validates an AISAC Agent API Key against monitored_assets table.
 * API Keys have format: aisac_<48 hex characters>
 *
 * @param supabase - Supabase client instance
 * @param apiKey - The API key to validate
 * @returns Validation result with tenant info if valid
 */
async function validateAssetApiKey(
  supabase: ReturnType<typeof createClient>,
  apiKey: string
): Promise<ApiKeyValidationResult> {
  // Check format
  if (!apiKey.startsWith('aisac_')) {
    return { valid: false, error: 'Invalid API key format' };
  }

  try {
    // Query asset by API key - include siem_config for SIEM filtering
    const { data: asset, error } = await supabase
      .from('monitored_assets')
      .select('id, tenant_id, name, ingestion_enabled, status, siem_config')
      .eq('api_key', apiKey)
      .maybeSingle();

    if (error) {
      safeError('API key validation query failed', error);
      return { valid: false, error: 'Database error during validation' };
    }

    if (!asset) {
      return { valid: false, error: 'API key not found' };
    }

    // Check if asset is enabled for ingestion
    if (!asset.ingestion_enabled) {
      return { valid: false, error: 'Asset ingestion is disabled' };
    }

    // Check if asset is not decommissioned
    if (asset.status === 'decommissioned') {
      return { valid: false, error: 'Asset is decommissioned' };
    }

    // Parse SIEM configuration from asset
    const siemConfig = asset.siem_config as SIEMConfig | null;
    const siemEnabled = siemConfig?.enabled === true;

    return {
      valid: true,
      tenantId: asset.tenant_id,
      assetId: asset.id,
      assetName: asset.name,
      siemEnabled, // Return SIEM status for conditional indexing
      siemConfig: siemConfig || undefined, // Full config for behavior control
    };
  } catch (error) {
    safeError('API key validation failed', error);
    return { valid: false, error: 'Validation error' };
  }
}

/**
 * Checks if a tenant has ANY assets with SIEM enabled.
 * Used for JWT auth where we don't know the specific asset.
 *
 * @param supabase - Supabase client instance
 * @param tenantId - The tenant ID to check
 * @returns Whether the tenant has at least one asset with SIEM enabled
 */
async function tenantHasSIEMEnabled(
  supabase: ReturnType<typeof createClient>,
  tenantId: string
): Promise<boolean> {
  try {
    const { count, error } = await supabase
      .from('monitored_assets')
      .select('id', { count: 'exact', head: true })
      .eq('tenant_id', tenantId)
      .eq('siem_config->enabled', true);

    if (error) {
      safeError('Failed to check tenant SIEM status', error);
      return false;
    }

    return (count ?? 0) > 0;
  } catch (error) {
    safeError('Error checking tenant SIEM status', error);
    return false;
  }
}

/**
 * Validates an asset by ID and returns its SIEM configuration.
 * Used for JWT auth where asset_id is provided in the request body.
 *
 * @param supabase - Supabase client instance
 * @param assetId - The asset ID to validate
 * @param tenantId - The expected tenant ID (for security validation)
 * @returns Validation result with SIEM config if valid
 */
async function validateAssetById(
  supabase: ReturnType<typeof createClient>,
  assetId: string,
  tenantId: string
): Promise<{
  valid: boolean;
  siemEnabled: boolean;
  siemConfig?: SIEMConfig;
  assetName?: string;
  error?: string;
}> {
  try {
    const { data: asset, error } = await supabase
      .from('monitored_assets')
      .select('id, tenant_id, name, ingestion_enabled, status, siem_config')
      .eq('id', assetId)
      .maybeSingle();

    if (error) {
      safeError('Asset validation query failed', error);
      return { valid: false, siemEnabled: false, error: 'Database error during validation' };
    }

    if (!asset) {
      return { valid: false, siemEnabled: false, error: 'Asset not found' };
    }

    // Security: Verify the asset belongs to the specified tenant
    if (asset.tenant_id !== tenantId) {
      safeLog(`[WARN] Security: Asset ${assetId} does not belong to tenant ${tenantId}`);
      return { valid: false, siemEnabled: false, error: 'Asset does not belong to this tenant' };
    }

    // Check if asset is enabled for ingestion
    if (!asset.ingestion_enabled) {
      return { valid: false, siemEnabled: false, error: 'Asset ingestion is disabled' };
    }

    // Check if asset is not decommissioned
    if (asset.status === 'decommissioned') {
      return { valid: false, siemEnabled: false, error: 'Asset is decommissioned' };
    }

    // Parse SIEM configuration from asset
    const siemConfig = asset.siem_config as SIEMConfig | null;
    const siemEnabled = siemConfig?.enabled === true;

    return {
      valid: true,
      siemEnabled,
      siemConfig: siemConfig || undefined,
      assetName: asset.name,
    };
  } catch (error) {
    safeError('Asset validation failed', error);
    return { valid: false, siemEnabled: false, error: 'Validation error' };
  }
}

/**
 * Updates asset heartbeat and counters after successful log ingestion
 *
 * @param supabase - Supabase client instance
 * @param assetId - The asset ID to update
 * @param messageCount - Number of messages ingested
 */
async function updateAssetHeartbeat(
  supabase: ReturnType<typeof createClient>,
  assetId: string,
  messageCount: number
): Promise<void> {
  try {
    await supabase
      .from('monitored_assets')
      .update({
        agent_last_seen: new Date().toISOString(),
        last_heartbeat: new Date().toISOString(),
        last_event_at: new Date().toISOString(),
        status: 'online',
        events_today: supabase.rpc('increment_events_today', {
          p_asset_id: assetId,
          p_count: messageCount,
        }),
        updated_at: new Date().toISOString(),
      })
      .eq('id', assetId);
  } catch (error) {
    // Non-critical error - log but don't fail the request
    safeError('Failed to update asset heartbeat', error);
  }
}

/**
 * Extracts the Bearer token from Authorization header
 */
function extractBearerToken(req: Request): string | null {
  // First check X-API-Key header (used by AISAC Agents for consistency)
  const xApiKey = req.headers.get('X-API-Key');
  if (xApiKey) {
    return xApiKey;
  }

  // Fallback to Authorization: Bearer header
  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

/**
 * Checks if a token is an AISAC API Key (vs JWT)
 */
function isAisacApiKey(token: string): boolean {
  return token.startsWith('aisac_');
}

// ============================================================================
// Syslog Parsing (RFC 3164 and RFC 5424)
// ============================================================================

/**
 * Parse syslog message (RFC 3164 and RFC 5424 formats)
 *
 * RFC 3164: <priority>timestamp hostname tag[pid]: message
 * RFC 5424: <priority>version timestamp hostname app-name procid msgid structured-data message
 *
 * @param rawMessage - Raw syslog message
 * @returns Parsed syslog structure
 */
function parseSyslogMessage(rawMessage: string): ParsedSyslog {
  const result: ParsedSyslog = {
    message: rawMessage,
    raw: rawMessage,
  };

  try {
    // Extract priority (between < >)
    const priorityMatch = rawMessage.match(/^<(\d+)>/);
    if (priorityMatch) {
      result.priority = parseInt(priorityMatch[1]);
      // Calculate facility and severity from priority
      // priority = facility * 8 + severity
      result.facility = Math.floor(result.priority / 8);
      result.severity = result.priority % 8;
    }

    // Detect RFC 5424 (has version number after priority)
    const rfc5424Match = rawMessage.match(
      /^<\d+>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/
    );
    if (rfc5424Match) {
      // RFC 5424 format
      result.timestamp = rfc5424Match[2];
      result.hostname = rfc5424Match[3];
      result.tag = rfc5424Match[4];
      result.message = rfc5424Match[7] || rawMessage;
    } else {
      // RFC 3164 format or partial format
      // Try to extract hostname and message after priority
      const contentAfterPriority = rawMessage.replace(/^<\d+>/, '').trim();

      // Try to extract timestamp (various formats)
      const timestampMatch = contentAfterPriority.match(
        /^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/
      );
      if (timestampMatch) {
        result.timestamp = timestampMatch[1];
      }

      // Try to extract hostname (first word after timestamp or priority)
      const parts = contentAfterPriority.split(/\s+/);
      if (parts.length > 0) {
        // Skip timestamp if present
        const startIdx = timestampMatch ? 3 : 0;
        if (parts[startIdx]) {
          result.hostname = parts[startIdx];
        }
      }

      // Extract message (everything after hostname and tag)
      const messageMatch = contentAfterPriority.match(/:\s*(.+)$/);
      if (messageMatch) {
        result.message = messageMatch[1].trim();
      }
    }

    // ========================================================================
    // PRIORITY 1: Detect Suricata EVE JSON format BEFORE text patterns
    //
    // This is critical because N8N may forward Suricata events with [n8n] prefix,
    // e.g.: "[n8n] {"timestamp":"...","event_type":"flow",...}"
    // Without this check, such messages would be misclassified as 'wazuh'
    // and the telemetry filter would never be applied.
    // ========================================================================
    let isEveJson = false;
    try {
      // Check if message contains JSON with event_type field (Suricata EVE signature)
      const jsonMatch = rawMessage.match(/\{[^{}]*"event_type"\s*:\s*"[^"]+"/);
      if (jsonMatch) {
        // Also verify it looks like valid EVE JSON (has timestamp or flow_id)
        if (rawMessage.includes('"timestamp"') || rawMessage.includes('"flow_id"')) {
          isEveJson = true;
          result.source = 'ids_suricata';
          safeLog(
            `[SEARCH] EVE JSON detected (event_type field found) -> forcing source=ids_suricata`
          );
        }
      }
    } catch {
      // Regex failed, continue with text pattern detection
    }

    // PRIORITY 2: Text-based source detection (only if not EVE JSON)
    if (!isEveJson) {
      if (rawMessage.includes('%ASA') || rawMessage.includes('%FTD')) {
        result.source = 'cisco_asa';
      } else if (rawMessage.includes('snort')) {
        result.source = 'ids_snort';
      } else if (rawMessage.includes('suricata')) {
        result.source = 'ids_suricata';
      } else if (
        // Wazuh/OSSEC alerts - detect various formats:
        // - N8N forwarded: "[n8n] (Rule 5557, Level 5) ..."
        // - Direct Wazuh: "ossec:" or "wazuh:" or "ossec-agent"
        // - Wazuh JSON: contains "rule" + "level" fields
        // NOTE: Only match [n8n] if it also has Wazuh patterns (Rule/Level)
        (rawMessage.includes('[n8n]') && /\(Rule\s+\d+,\s*Level\s+\d+\)/i.test(rawMessage)) ||
        rawMessage.includes('ossec:') ||
        rawMessage.includes('wazuh:') ||
        rawMessage.includes('ossec-agent')
      ) {
        result.source = 'wazuh';
      } else if (rawMessage.includes('sshd')) {
        result.source = 'syslog_ssh';
      } else {
        result.source = 'generic_syslog';
      }
    }
  } catch (error) {
    // If parsing fails, return basic structure with raw message
    safeError('Syslog parsing failed (using fallback)', error);
    result.message = rawMessage;
    result.source = 'syslog';
  }

  return result;
}

// ============================================================================
// Suricata EVE JSON Parsing
// ============================================================================

/**
 * Try to extract Suricata EVE JSON from a syslog message.
 *
 * Suricata logs in EVE (Extensible Event Format) as JSON embedded in syslog:
 *   <14>Jan 28 12:00:00 host suricata: {"timestamp":"...","event_type":"alert",...}
 *
 * Or sometimes just raw JSON when sent directly.
 */
function tryExtractSuricataEve(message: string): Record<string, unknown> | null {
  try {
    const trimmed = message.trim();

    // Case 1: message is pure JSON
    if (trimmed.startsWith('{')) {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') {
        // Case 1a: event_type at top level (raw EVE JSON)
        if ('event_type' in parsed) {
          return parsed as Record<string, unknown>;
        }
        // Case 1b: event_type inside fields object (agent wrapper format)
        if (
          'fields' in parsed &&
          parsed.fields &&
          typeof parsed.fields === 'object' &&
          'event_type' in parsed.fields
        ) {
          return parsed.fields as Record<string, unknown>;
        }
      }
    }

    // Case 2: JSON is embedded after syslog header (find first '{')
    const jsonStart = message.indexOf('{');
    if (jsonStart > 0) {
      const jsonStr = message.substring(jsonStart);
      const parsed = JSON.parse(jsonStr);
      if (parsed && typeof parsed === 'object') {
        // Case 2a: event_type at top level
        if ('event_type' in parsed) {
          return parsed as Record<string, unknown>;
        }
        // Case 2b: event_type inside fields object (agent wrapper format)
        if (
          'fields' in parsed &&
          parsed.fields &&
          typeof parsed.fields === 'object' &&
          'event_type' in parsed.fields
        ) {
          return parsed.fields as Record<string, unknown>;
        }
      }
    }
  } catch {
    // Not valid JSON -- fall through
  }
  return null;
}

/**
 * Parse a Suricata EVE JSON object into a NormalizedAlert.
 *
 * Handles:
 * - alert events -> proper severity + signature + category
 * - stats/flow/dns/http/tls -> severity 'info' (filtered by min_severity)
 * - anomaly/drop -> severity 'low'
 */
function normalizeSuricataEve(eve: Record<string, unknown>, rawMessage: string): NormalizedAlert {
  const eventType = String(eve.event_type || 'unknown');

  // Extract common network fields
  const srcIp = eve.src_ip ? String(eve.src_ip) : '';
  const destIp = eve.dest_ip ? String(eve.dest_ip) : '';
  const proto = eve.proto ? String(eve.proto).toUpperCase() : '';
  const entities: NormalizedAlert['entities'] = {};

  const ips: string[] = [];
  if (srcIp) ips.push(srcIp);
  if (destIp && destIp !== srcIp) ips.push(destIp);
  if (ips.length > 0) entities.ips = ips;

  // Extract ports - store both in array for backwards compatibility AND explicit fields
  const srcPort = typeof eve.src_port === 'number' ? eve.src_port : null;
  const destPort = typeof eve.dest_port === 'number' ? eve.dest_port : null;

  const ports: number[] = [];
  if (srcPort !== null) ports.push(srcPort);
  if (destPort !== null && destPort !== srcPort) ports.push(destPort);
  if (ports.length > 0) entities.ports = ports;

  // ---- Alert events (actual security detections) ----
  if (eventType === 'alert' && eve.alert && typeof eve.alert === 'object') {
    const alert = eve.alert as Record<string, unknown>;
    const signature = String(alert.signature || alert.signature_id || 'Unknown Suricata Alert');
    const category = String(alert.category || 'Uncategorized');
    const sid = alert.signature_id ? String(alert.signature_id) : null;

    // Suricata severity scale: 1 = high, 2 = medium, 3 = low
    const sevNum = Number(alert.severity);
    let severity: SeverityLevel;
    switch (sevNum) {
      case 1:
        severity = 'high';
        break;
      case 2:
        severity = 'medium';
        break;
      case 3:
        severity = 'low';
        break;
      default:
        severity = 'info';
        break;
    }

    // Map signature keywords to alert type
    let type: AlertType = 'network_intrusion';
    const sigLower = signature.toLowerCase();
    if (
      sigLower.includes('malware') ||
      sigLower.includes('trojan') ||
      sigLower.includes('ransomware')
    ) {
      type = 'malware';
    } else if (sigLower.includes('phish')) {
      type = 'phishing';
    } else if (sigLower.includes('dos') || sigLower.includes('flood')) {
      type = 'ddos';
    } else if (sigLower.includes('exploit') || sigLower.includes('cve-')) {
      type = 'vulnerability_exploit';
    } else if (sigLower.includes('brute') || sigLower.includes('password')) {
      type = 'brute_force';
    } else if (sigLower.includes('exfil') || sigLower.includes('leak')) {
      type = 'data_exfiltration';
    }

    const sidLabel = sid ? ` [SID:${sid}]` : '';
    const flow = srcIp && destIp ? ` -- ${srcIp} -> ${destIp}` : '';
    const protoLabel = proto ? ` (${proto})` : '';

    return {
      source: 'ids_suricata',
      severity,
      type,
      title: `${signature}${sidLabel}`,
      description: `${category}${flow}${protoLabel}`,
      timestamp: String(eve.timestamp || new Date().toISOString()),
      entities,
      protocol: proto || null,
      src_port: srcPort,
      dest_port: destPort,
      src_ip: srcIp || null,
      dest_ip: destIp || null,
      raw_data: eve,
    };
  }

  // ---- Non-alert events (stats, flow, dns, http, tls, etc.) ----
  const typeLabels: Record<string, string> = {
    stats: 'Suricata Engine Statistics',
    flow: 'Network Flow Record',
    dns: 'DNS Query',
    http: 'HTTP Transaction',
    tls: 'TLS Handshake',
    fileinfo: 'File Transfer',
    anomaly: 'Protocol Anomaly',
    drop: 'Dropped Packet',
  };

  const title = typeLabels[eventType] || `Suricata ${eventType}`;
  const flow = srcIp && destIp ? ` -- ${srcIp} -> ${destIp}` : '';
  const protoLabel = proto ? ` (${proto})` : '';

  return {
    source: 'ids_suricata',
    severity: eventType === 'anomaly' || eventType === 'drop' ? 'low' : 'info',
    type: eventType === 'anomaly' ? 'anomaly' : 'other',
    title,
    description: `${eventType} event${flow}${protoLabel}`,
    timestamp: String(eve.timestamp || new Date().toISOString()),
    entities,
    protocol: proto || null,
    src_port: srcPort,
    dest_port: destPort,
    src_ip: srcIp || null,
    dest_ip: destIp || null,
    raw_data: eve,
  };
}

// ============================================================================
// Wazuh Agent Resolution (Collector -> Real Asset Routing)
// ============================================================================

/**
 * In-memory cache for Wazuh agent name -> asset_id resolution.
 * Avoids a DB query per alert when a batch contains many alerts from the same agent.
 * TTL: 60 seconds (resets on function cold start).
 */
const agentAssetCache = new Map<
  string,
  { assetId: string | null; siemEnabled: boolean; expiresAt: number }
>();
const AGENT_CACHE_TTL_MS = 60_000;

/**
 * Extract Wazuh agent info (name, id, ip) from a raw syslog message containing Wazuh JSON.
 *
 * Wazuh alerts arrive in formats like:
 *   wazuh: {"timestamp":"...","rule":{...},"agent":{"id":"002","name":"wazuh-aisac-staging-linux","ip":"172.31.25.179"},...}
 *
 * The agent.name is the configured Wazuh agent name (format: wazuh-<asset_name>),
 * which identifies the real host that generated the alert.
 * This may differ from the collector (Wazuh Manager) that forwarded it.
 */
function extractWazuhAgentInfo(message: string): { name: string; id: string; ip: string } | null {
  try {
    const jsonStart = message.indexOf('{');
    if (jsonStart < 0) return null;

    const parsed = JSON.parse(message.substring(jsonStart));
    if (parsed.agent && typeof parsed.agent === 'object' && typeof parsed.agent.name === 'string') {
      return {
        name: parsed.agent.name,
        id: String(parsed.agent.id || ''),
        ip: String(parsed.agent.ip || ''),
      };
    }
  } catch {
    // Not valid JSON or no agent field
  }
  return null;
}

/**
 * Resolve the real asset_id for a Wazuh agent by matching against monitored_assets.
 *
 * Resolution priority:
 *   1. integration_config->>'wazuh_agent_name' = agent.name (exact, set by install script)
 *   2. find_asset_by_identifier() RPC (ILIKE on hostname/name + IP, DB function)
 *   3. null -> caller falls back to collector asset_id
 *
 * Uses an in-memory cache (60s TTL) to avoid repeated DB queries for the same agent.
 *
 * @param agentName - The Wazuh agent.name (e.g., "wazuh-aisac-staging-linux")
 * @param agentIp - The Wazuh agent.ip (e.g., "172.31.25.179"), used for fallback resolution
 */
async function resolveWazuhAgentAsset(
  supabase: ReturnType<typeof createClient>,
  tenantId: string,
  agentName: string,
  agentIp?: string
): Promise<{ assetId: string; siemEnabled: boolean } | null> {
  const cacheKey = `${tenantId}:${agentName}`;
  const cached = agentAssetCache.get(cacheKey);

  if (cached && Date.now() < cached.expiresAt) {
    if (cached.assetId) {
      return { assetId: cached.assetId, siemEnabled: cached.siemEnabled };
    }
    return null;
  }

  try {
    // Priority 1: Exact match on integration_config->>'wazuh_agent_name'
    // This field is set by the Wazuh install script via PATCH /agent-register
    const { data: asset } = await supabase
      .from('monitored_assets')
      .select('id, siem_config')
      .eq('tenant_id', tenantId)
      .eq('integration_config->>wazuh_agent_name', agentName)
      .neq('status', 'decommissioned')
      .limit(1)
      .maybeSingle();

    if (asset) {
      const siemEnabled = (asset.siem_config as SIEMConfig | null)?.enabled === true;
      agentAssetCache.set(cacheKey, {
        assetId: asset.id,
        siemEnabled,
        expiresAt: Date.now() + AGENT_CACHE_TTL_MS,
      });
      safeLog(`[ROUTE] Resolved agent "${agentName}" -> asset ${asset.id} via integration_config`);
      return { assetId: asset.id, siemEnabled };
    }

    // Priority 2: DB function find_asset_by_identifier (ILIKE on hostname/name + IP)
    // Covers assets not yet updated by install script, or manual configurations
    if (agentIp || agentName) {
      const { data: rpcAssetId } = await supabase.rpc('find_asset_by_identifier', {
        p_tenant_id: tenantId,
        p_ip: agentIp || null,
        p_hostname: agentName,
      });

      if (rpcAssetId) {
        // Fetch siem_config for the resolved asset
        const { data: resolvedAsset } = await supabase
          .from('monitored_assets')
          .select('siem_config')
          .eq('id', rpcAssetId)
          .maybeSingle();

        const siemEnabled = (resolvedAsset?.siem_config as SIEMConfig | null)?.enabled === true;
        agentAssetCache.set(cacheKey, {
          assetId: rpcAssetId,
          siemEnabled,
          expiresAt: Date.now() + AGENT_CACHE_TTL_MS,
        });
        safeLog(
          `[ROUTE] Resolved agent "${agentName}" -> asset ${rpcAssetId} via find_asset_by_identifier`
        );
        return { assetId: rpcAssetId, siemEnabled };
      }
    }

    // No match -- cache the miss to avoid repeated lookups
    agentAssetCache.set(cacheKey, {
      assetId: null,
      siemEnabled: false,
      expiresAt: Date.now() + AGENT_CACHE_TTL_MS,
    });
    safeLog(
      `[ROUTE] No asset found for agent "${agentName}" (ip: ${agentIp || 'none'}) -- will use collector`
    );
    return null;
  } catch (error) {
    safeError(`Failed to resolve Wazuh agent asset for "${agentName}"`, error);
    return null;
  }
}

// ============================================================================
// Wazuh Network Info Extraction (from full JSON)
// ============================================================================

/**
 * Extracts network information (IPs, ports) and real hostname from the full
 * Wazuh JSON payload. Wazuh stores IPs in different locations depending on
 * the event source:
 * - Linux/generic: data.srcip, data.dstip
 * - Windows Security: data.win.eventdata.ipAddress, data.win.eventdata.ipPort
 * - Agent itself: agent.ip (the host that generated the alert)
 */
function extractWazuhNetworkInfo(message: string): {
  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  hostname: string | null;
} | null {
  try {
    const jsonStart = message.indexOf('{');
    if (jsonStart < 0) return null;

    const parsed = JSON.parse(message.substring(jsonStart));
    let srcIp: string | null = null;
    let dstIp: string | null = null;
    let srcPort: number | null = null;
    let hostname: string | null = null;

    // Extract hostname from agent.name (more reliable than syslog prefix "wazuh:")
    if (parsed.agent?.name) {
      hostname = String(parsed.agent.name);
    } else if (parsed.manager?.name) {
      hostname = String(parsed.manager.name);
    }

    // Priority 1: data.srcip / data.dstip (Linux/generic Wazuh events)
    if (parsed.data?.srcip) {
      srcIp = String(parsed.data.srcip);
    }
    if (parsed.data?.dstip) {
      dstIp = String(parsed.data.dstip);
    }

    // Priority 2: Windows Security events (data.win.eventdata.ipAddress)
    if (!srcIp && parsed.data?.win?.eventdata?.ipAddress) {
      const ip = String(parsed.data.win.eventdata.ipAddress);
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        srcIp = ip;
      }
    }
    if (parsed.data?.win?.eventdata?.ipPort) {
      const port = parseInt(String(parsed.data.win.eventdata.ipPort), 10);
      if (port > 0 && port <= 65535) {
        srcPort = port;
      }
    }

    // Priority 3: agent.ip as destination (the target host)
    if (!dstIp && parsed.agent?.ip) {
      const agentIp = String(parsed.agent.ip);
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(agentIp)) {
        dstIp = agentIp;
      }
    }

    return { srcIp, dstIp, srcPort, hostname };
  } catch {
    return null;
  }
}

// ============================================================================
// Wazuh/OSSEC Alert Parsing
// ============================================================================

/**
 * Extract Wazuh alert data from a message.
 *
 * Wazuh alerts from N8N come in format:
 *   "[n8n] (Rule 5557, Level 5) unix_chkpwd: Password check failed. [MIT..."
 *
 * Or direct Wazuh format:
 *   "ossec: Alert Level: 5; Rule: 5557 - 'unix_chkpwd: Password check failed'"
 *
 * @returns Extracted rule ID, level, and description, or null if not Wazuh format
 */
function tryExtractWazuhData(
  message: string
): { ruleId: string; level: number; description: string } | null {
  try {
    // Pattern 1: N8N forwarded format "[n8n] (Rule XXXX, Level Y) description"
    const n8nPattern = /\[n8n\]\s*\(Rule\s+(\d+),\s*Level\s+(\d+)\)\s*(.+)/i;
    const n8nMatch = message.match(n8nPattern);
    if (n8nMatch) {
      return {
        ruleId: n8nMatch[1],
        level: parseInt(n8nMatch[2], 10),
        description: n8nMatch[3].trim(),
      };
    }

    // Pattern 2: Generic Wazuh format "(Rule XXXX, Level Y) description"
    const genericPattern = /\(Rule\s+(\d+),\s*Level\s+(\d+)\)\s*(.+)/i;
    const genericMatch = message.match(genericPattern);
    if (genericMatch) {
      return {
        ruleId: genericMatch[1],
        level: parseInt(genericMatch[2], 10),
        description: genericMatch[3].trim(),
      };
    }

    // Pattern 3: OSSEC format "Alert Level: X; Rule: YYYY - 'description'"
    const ossecPattern = /Alert\s+Level:\s*(\d+);\s*Rule:\s*(\d+)\s*-\s*['"]?(.+?)['"]?$/i;
    const ossecMatch = message.match(ossecPattern);
    if (ossecMatch) {
      return {
        ruleId: ossecMatch[2],
        level: parseInt(ossecMatch[1], 10),
        description: ossecMatch[3].trim(),
      };
    }

    // Pattern 4: Try to parse as JSON (Wazuh API format)
    if (message.includes('{')) {
      const jsonStart = message.indexOf('{');
      const jsonStr = message.substring(jsonStart);
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.rule && typeof parsed.rule.level === 'number') {
          return {
            ruleId: String(parsed.rule.id || parsed.rule.sidid || 'unknown'),
            level: parsed.rule.level,
            description: parsed.rule.description || parsed.full_log || message,
          };
        }
      } catch {
        // Not valid JSON, continue
      }
    }
  } catch {
    // Parsing failed
  }
  return null;
}

/**
 * Normalize a Wazuh/OSSEC alert into AISAC format.
 *
 * Wazuh uses a severity scale of 0-15:
 * - Level 0-3: low (syslog-like informational)
 * - Level 4-7: medium (authentication, policy events)
 * - Level 8-11: high (attacks, critical events)
 * - Level 12-15: critical (severe attacks, rootkits)
 *
 * @param parsed - Parsed syslog message
 * @param wazuhData - Extracted Wazuh rule/level data
 * @returns Normalized alert
 */
function normalizeWazuhAlert(
  parsed: ParsedSyslog,
  wazuhData: { ruleId: string; level: number; description: string }
): NormalizedAlert {
  // Map Wazuh level (0-15) to AISAC severity
  // This is the CORRECT mapping per Wazuh documentation
  let severity: SeverityLevel;
  if (wazuhData.level >= 12) {
    severity = 'critical';
  } else if (wazuhData.level >= 8) {
    severity = 'high';
  } else if (wazuhData.level >= 4) {
    severity = 'medium';
  } else {
    severity = 'low';
  }

  // Determine alert type based on description content
  let type: AlertType = 'other';
  const lowerDesc = wazuhData.description.toLowerCase();

  if (
    lowerDesc.includes('authentication') ||
    lowerDesc.includes('password') ||
    lowerDesc.includes('login') ||
    lowerDesc.includes('pam') ||
    lowerDesc.includes('sshd') ||
    lowerDesc.includes('failed') ||
    lowerDesc.includes('invalid user')
  ) {
    type = 'unauthorized_access';
  } else if (lowerDesc.includes('brute') || lowerDesc.includes('multiple failed')) {
    type = 'brute_force';
  } else if (
    lowerDesc.includes('malware') ||
    lowerDesc.includes('rootkit') ||
    lowerDesc.includes('trojan')
  ) {
    type = 'malware';
  } else if (
    lowerDesc.includes('intrusion') ||
    lowerDesc.includes('attack') ||
    lowerDesc.includes('exploit')
  ) {
    type = 'network_intrusion';
  } else if (
    lowerDesc.includes('policy') ||
    lowerDesc.includes('violation') ||
    lowerDesc.includes('compliance')
  ) {
    type = 'policy_violation';
  } else if (lowerDesc.includes('anomaly') || lowerDesc.includes('unusual')) {
    type = 'anomaly';
  }

  // Extract entities from description
  const entities: NormalizedAlert['entities'] = {};

  // Extract IPs
  const ipPattern =
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const ips = wazuhData.description.match(ipPattern);
  if (ips && ips.length > 0) {
    entities.ips = Array.from(new Set(ips));
  }

  // Extract usernames
  const userPatterns = [
    /user[:\s]+['"]?([a-zA-Z0-9._-]+)['"]?/i,
    /for\s+['"]?([a-zA-Z0-9._-]+)['"]?\s+from/i,
    /invalid user\s+['"]?([a-zA-Z0-9._-]+)['"]?/i,
    /account[:\s]+['"]?([a-zA-Z0-9._-]+)['"]?/i,
  ];
  for (const pattern of userPatterns) {
    const match = wazuhData.description.match(pattern);
    if (match && match[1]) {
      entities.users = [match[1]];
      break;
    }
  }

  // Extract ports
  const portPatterns = [/\bport\s+(\d{1,5})\b/gi, /:(\d{1,5})\b/g];
  const ports: number[] = [];
  for (const pattern of portPatterns) {
    let portMatch;
    while ((portMatch = pattern.exec(wazuhData.description)) !== null) {
      const port = parseInt(portMatch[1], 10);
      if (port > 0 && port <= 65535 && !ports.includes(port)) {
        ports.push(port);
      }
    }
  }
  if (ports.length > 0) {
    entities.ports = ports;
  }

  // Build title: WAZUH - SEVERITY - Rule ID
  const severityLabel = severity.toUpperCase();
  const title = `WAZUH - ${severityLabel} - Rule ${wazuhData.ruleId}`;

  // Extract explicit src_ip and dest_ip from entities.ips[] for OpenSearch aggregations
  // First IP in array is typically the source (attacker/initiator), second is destination (target)
  const extractedIps = entities.ips || [];
  const srcIp = extractedIps[0] || null;
  const destIp = extractedIps[1] || null;

  // Extract explicit src_port and dest_port from entities.ports[]
  // First port is typically source, second is destination
  const extractedPorts = entities.ports || [];
  const srcPort = extractedPorts[0] || null;
  const destPort = extractedPorts[1] || null;

  return {
    source: 'wazuh',
    severity,
    type,
    title,
    description: wazuhData.description,
    timestamp: parsed.timestamp || new Date().toISOString(),
    entities,
    protocol: null,
    // Add explicit IP and port fields for OpenSearch aggregations
    src_ip: srcIp,
    dest_ip: destIp,
    src_port: srcPort,
    dest_port: destPort,
    raw_data: {
      rule_id: wazuhData.ruleId,
      level: wazuhData.level,
      original_message: parsed.raw,
      hostname: parsed.hostname,
    },
  };
}

// ============================================================================
// Alert Normalization (advanced)
// ============================================================================

// NOTE: alertNormalizer from src/utils/ cannot be imported in Edge Functions
// (outside supabase/functions/ scope). All normalization is handled inline
// by normalizeSyslogToAlert, normalizeSuricataEve, and normalizeWazuhAlert.

/**
 * Normalize parsed syslog into AISAC alert format
 *
 * @param parsed - Parsed syslog message
 * @returns Normalized alert
 */
function normalizeSyslogToAlert(parsed: ParsedSyslog): NormalizedAlert {
  // Map syslog severity (0-7) to AISAC severity
  const severityMap: Record<number, SeverityLevel> = {
    0: 'critical', // Emergency
    1: 'critical', // Alert
    2: 'critical', // Critical
    3: 'high', // Error
    4: 'medium', // Warning
    5: 'low', // Notice
    6: 'info', // Informational
    7: 'info', // Debug
  };

  const severity = parsed.severity !== undefined ? severityMap[parsed.severity] || 'info' : 'info';

  // Determine alert type based on message content
  let type: AlertType = 'other';
  const lowerMessage = parsed.message.toLowerCase();

  if (
    lowerMessage.includes('deny') ||
    lowerMessage.includes('denied') ||
    lowerMessage.includes('blocked')
  ) {
    type = 'network_intrusion';
  } else if (lowerMessage.includes('fail') || lowerMessage.includes('failed')) {
    type = 'unauthorized_access';
  } else if (lowerMessage.includes('intrusion') || lowerMessage.includes('attack')) {
    type = 'network_intrusion';
  } else if (lowerMessage.includes('malware') || lowerMessage.includes('virus')) {
    type = 'malware';
  } else if (lowerMessage.includes('dos') || lowerMessage.includes('flood')) {
    type = 'ddos';
  }

  // Extract entities (IPs, users, etc.)
  const entities: NormalizedAlert['entities'] = {};

  // Extract IPs (IPv4 pattern)
  const ipPattern =
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const ips = parsed.message.match(ipPattern);
  if (ips && ips.length > 0) {
    entities.ips = Array.from(new Set(ips));
  }

  // Extract usernames (common patterns)
  const userPatterns = [
    /user[:\s]+([a-zA-Z0-9._-]+)/i,
    /for\s+([a-zA-Z0-9._-]+)\s+from/i,
    /account[:\s]+([a-zA-Z0-9._-]+)/i,
  ];

  for (const pattern of userPatterns) {
    const match = parsed.message.match(pattern);
    if (match && match[1]) {
      entities.users = [match[1]];
      break;
    }
  }

  // Extract ports (common patterns: port 22, dst_port=8080, DPT=80, IP:port)
  // NOTE: We use explicit patterns to avoid matching timestamp components like "12:34:56"
  const portPatterns = [
    /\bport\s+(\d{1,5})\b/gi,
    /\b(?:dst_port|dport|DPT|dest_port|destination_port)[=:\s]+(\d{1,5})\b/gi,
    /\b(?:src_port|sport|SPT|source_port)[=:\s]+(\d{1,5})\b/gi,
    // IPv4:port pattern - require valid IP prefix to avoid timestamp matches
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d{1,5})\b/g,
  ];

  const ports: number[] = [];
  for (const pattern of portPatterns) {
    let portMatch;
    while ((portMatch = pattern.exec(parsed.message)) !== null) {
      const port = parseInt(portMatch[1], 10);
      // Validate port range and avoid duplicates
      // Note: We accept all valid port numbers (1-65535) as some services use low ports
      if (port > 0 && port <= 65535 && !ports.includes(port)) {
        ports.push(port);
      }
    }
  }
  if (ports.length > 0) {
    entities.ports = ports;
  }

  // Extract protocol (TCP, UDP, ICMP, etc.)
  const protoPatterns = [
    /\b(?:proto|protocol|PROTO)=?(TCP|UDP|ICMP|GRE|ESP|AH)\b/gi,
    /\b(TCP|UDP|ICMP)\b/g,
  ];

  let protocol: string | null = null;
  for (const pattern of protoPatterns) {
    const protoMatch = parsed.message.match(pattern);
    if (protoMatch && protoMatch[0]) {
      protocol = protoMatch[0].replace(/^(?:proto|protocol|PROTO)=?/i, '').toUpperCase();
      break;
    }
  }

  // Create title from source and severity
  const sourceLabel = parsed.source?.replace(/_/g, ' ').toUpperCase() || 'SYSLOG';
  const title = `${sourceLabel} - ${severity.toUpperCase()} - ${parsed.hostname || 'Unknown Host'}`;

  // Extract explicit src_ip and dest_ip from entities.ips[] for OpenSearch aggregations
  // First IP in array is typically the source (attacker/initiator), second is destination (target)
  const extractedIps = entities.ips || [];
  const srcIp = extractedIps[0] || null;
  const destIp = extractedIps[1] || null;

  // Extract explicit src_port and dest_port from entities.ports[]
  // First port is typically source, second is destination
  const extractedPorts = entities.ports || [];
  const srcPort = extractedPorts[0] || null;
  const destPort = extractedPorts[1] || null;

  return {
    source: parsed.source || 'syslog',
    severity,
    type,
    title,
    description: parsed.message,
    timestamp: new Date().toISOString(), // Use current time if no timestamp
    entities,
    protocol,
    // Add explicit IP and port fields for OpenSearch aggregations
    src_ip: srcIp,
    dest_ip: destIp,
    src_port: srcPort,
    dest_port: destPort,
    raw_data: {
      priority: parsed.priority,
      facility: parsed.facility,
      severity: parsed.severity,
      hostname: parsed.hostname,
      timestamp: parsed.timestamp,
      raw: parsed.raw,
    },
  };
}

// ============================================================================
// OpenSearch Indexing for SIEM Dashboard
// ============================================================================

/**
 * Indexes normalized alerts to OpenSearch for SIEM dashboard visibility.
 * The SIEM dashboard queries OpenSearch directly via siem-query edge function.
 *
 * CRITICAL: Both tenantId and assetId are REQUIRED for multi-tenant/multi-asset
 * data isolation. Events without these fields will not be properly filtered
 * in the siem-query function.
 *
 * @param alerts - Normalized alerts to index
 * @param tenantId - Tenant ID (required for multi-tenant isolation)
 * @param assetId - Asset ID (required for multi-asset SIEM filtering)
 * @returns Object with indexed count and any errors
 */
async function indexToOpenSearch(
  alerts: NormalizedAlert[],
  tenantId: string,
  assetId: string // MANDATORY - no longer optional
): Promise<{ indexed: number; errors: string[] }> {
  const opensearchUrl = Deno.env.get('OPENSEARCH_API_URL');
  const opensearchApiKey = Deno.env.get('OPENSEARCH_API_KEY');

  if (!opensearchUrl || !opensearchApiKey) {
    safeLog('[WARN] OpenSearch not configured - skipping SIEM indexing');
    return { indexed: 0, errors: ['OpenSearch not configured'] };
  }

  const indexName = `siem-events-${new Date().toISOString().substring(0, 10).replace(/-/g, '.')}`;
  const errors: string[] = [];
  let indexed = 0;

  // Ensure index exists (create if not)
  try {
    const indexExistsResponse = await fetch(`${opensearchUrl}/${indexName}`, {
      method: 'HEAD',
      headers: { 'X-API-Key': opensearchApiKey },
      signal: AbortSignal.timeout(5000),
    });

    if (indexExistsResponse.status === 404) {
      safeLog(`[NOTE] Creating index ${indexName}...`);
      const createIndexResponse = await fetch(`${opensearchUrl}/${indexName}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': opensearchApiKey,
        },
        body: JSON.stringify({
          settings: {
            number_of_shards: 1,
            number_of_replicas: 0,
          },
          mappings: {
            properties: {
              '@timestamp': { type: 'date' },
              timestamp: { type: 'date' },
              indexed_at: { type: 'date' },
              severity: { type: 'integer' },
              severity_label: { type: 'keyword' },
              dataset: { type: 'keyword' },
              kind: { type: 'keyword' },
              category: { type: 'keyword' },
              type: { type: 'keyword' },
              scanner: { type: 'keyword' },
              source_ip: { type: 'ip' },
              destination_ip: { type: 'ip' },
              src_ip: { type: 'ip' }, // Suricata-style field for aggregation
              dest_ip: { type: 'ip' }, // Suricata-style field for aggregation
              dest_port: { type: 'integer' },
              src_port: { type: 'integer' },
              app_proto: { type: 'keyword' },
              message: { type: 'text' },
              event_type: { type: 'keyword' },
              tenant_id: { type: 'keyword' },
              asset_id: { type: 'keyword' }, // Top-level asset_id for filtering
              dedup_key: { type: 'keyword' }, // For deduplication
              occurrence_count: { type: 'integer' }, // Track duplicate occurrences
              labels: {
                type: 'object',
                properties: {
                  tenant_id: { type: 'keyword' },
                  asset_id: { type: 'keyword' }, // For asset-based SIEM filtering
                },
              },
              metadata: {
                type: 'object',
                properties: {
                  tenant_id: { type: 'keyword' },
                  asset_id: { type: 'keyword' }, // For asset-based SIEM filtering
                  source: { type: 'keyword' },
                  title: { type: 'text' },
                },
              },
              entities: {
                type: 'object',
                properties: {
                  ips: { type: 'ip' },
                  ports: { type: 'integer' }, // For port aggregations fallback
                },
              },
              raw: { type: 'object', enabled: false },
            },
          },
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (!createIndexResponse.ok) {
        const errorText = await createIndexResponse.text();
        safeError(`[ERR] Failed to create index: ${errorText}`);
        errors.push(`Failed to create index: ${errorText}`);
        return { indexed: 0, errors };
      }
      safeLog(`[OK] Index ${indexName} created successfully`);
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    safeError(`[ERR] Error checking/creating index: ${errorMsg}`);
    errors.push(`Index creation error: ${errorMsg}`);
    return { indexed: 0, errors };
  }

  // Build bulk request body (NDJSON format)
  const bulkBody: string[] = [];

  // Helper function to generate dedup_key for OpenSearch.
  // CRITICAL: must include assetId AND wazuh_agent_name so that events from
  // different agents (even when all routed to the collector as fallback) never
  // overwrite each other.  Without this, two agents firing the same rule with
  // the same severity produce identical document IDs and one silently overwrites
  // the other, causing missing events in the SIEM dashboard.
  function generateOpenSearchDedupKey(alert: NormalizedAlert, tid: string, aid: string): string {
    const normalizedTitle = (alert.title || 'unknown')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .substring(0, 100);
    // Include agent name so per-agent events are always distinct documents,
    // even when asset routing falls back to the collector's asset_id.
    const agentPart = alert.wazuh_agent_name
      ? `_${alert.wazuh_agent_name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`
      : '';
    return `${tid}_${aid}${agentPart}_${alert.source}_${alert.severity}_${normalizedTitle}`;
  }

  // Simple hash function for generating document ID from dedup_key
  function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    // Convert to hex and ensure positive
    return Math.abs(hash).toString(16).padStart(8, '0');
  }

  for (const alert of alerts) {
    // Map AISAC severity to numeric value (0-4)
    const severityMap: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };

    // Generate dedup_key for this alert (includes assetId + agent_name)
    const dedupKey = generateOpenSearchDedupKey(alert, tenantId, assetId);
    // Create a unique document ID from the dedup_key
    // This ensures duplicate alerts update existing documents instead of creating new ones
    const docId = `${simpleHash(dedupKey)}_${dedupKey.substring(0, 50)}`;

    // Create document in SIEM format that siem-query expects
    // asset_id is stored at multiple levels for flexible filtering:
    // - Top-level for direct filtering (most efficient)
    // - labels.asset_id for compatibility with existing queries
    // - metadata.asset_id for context
    //
    // IMPORTANT: Only include port fields when they have actual values.
    // OpenSearch terms aggregations don't count null values - they need the field
    // to be missing or have a real value. Setting dest_port: null causes empty aggregations.
    const doc: Record<string, unknown> = {
      '@timestamp': alert.timestamp,
      timestamp: alert.timestamp,
      indexed_at: new Date().toISOString(),
      severity: severityMap[alert.severity] ?? 3,
      severity_label: alert.severity,
      dataset: alert.source || 'syslog',
      kind: 'alert',
      category: alert.type || 'syslog',
      type: alert.type || 'syslog',
      scanner: alert.source || 'syslog',
      source_ip: alert.entities?.ips?.[0] || null,
      destination_ip: alert.entities?.ips?.[1] || null,
      message: alert.description || alert.title,
      event_type: 'alert', // Important for severity aggregation in siem-query
      // Multi-tenant isolation: tenant_id in multiple locations for flexible querying
      tenant_id: tenantId,
      // Asset identification for SIEM filtering (MANDATORY for multi-asset isolation)
      asset_id: assetId,
      // Deduplication fields
      dedup_key: dedupKey,
      occurrence_count: 1, // Will be overwritten on duplicates
      labels: {
        tenant_id: tenantId,
        asset_id: assetId,
      },
      metadata: {
        tenant_id: tenantId,
        asset_id: assetId,
        source: alert.source,
        title: alert.title,
      },
      // Store raw_data but ensure MITRE data is extractable for aggregations
      raw: (() => {
        // Try to parse and structure raw_data for better MITRE aggregations
        if (!alert.raw_data) return {};

        // If it's a string, try to parse it
        if (typeof alert.raw_data === 'string') {
          try {
            return JSON.parse(alert.raw_data);
          } catch {
            return { original: alert.raw_data };
          }
        }

        // If it's already an object, return it
        return alert.raw_data;
      })(),
    };

    // Add Wazuh agent fields at root level so siem-query and the SIEM frontend
    // can use agent_name to scope per-agent deduplication correctly.
    if (alert.wazuh_agent_name) {
      doc.agent_name = alert.wazuh_agent_name;
    }
    if (alert.wazuh_agent_id) {
      doc.agent_id = alert.wazuh_agent_id;
    }

    // Only add port fields if they have actual numeric values
    // This ensures OpenSearch aggregations work correctly (null values are not counted)
    if (typeof alert.dest_port === 'number') {
      doc.dest_port = alert.dest_port;
    }
    if (typeof alert.src_port === 'number') {
      doc.src_port = alert.src_port;
    }
    if (alert.protocol) {
      doc.app_proto = alert.protocol;
    }

    // Add Suricata-style IP fields for aggregation (separate from normalized source_ip/destination_ip)
    // This ensures aggregations work even when src_ip === dest_ip
    if (alert.src_ip) {
      doc.src_ip = alert.src_ip;
    }
    if (alert.dest_ip) {
      doc.dest_ip = alert.dest_ip;
    }

    // Include entities object for port aggregation fallback
    // entities.ports contains both src and dest ports as an array
    if (alert.entities && (alert.entities.ips?.length || alert.entities.ports?.length)) {
      doc.entities = alert.entities;
    }

    // Bulk index action with explicit _id for deduplication
    // Using the same _id will overwrite existing documents (update instead of create duplicate)
    bulkBody.push(JSON.stringify({ index: { _index: indexName, _id: docId } }));
    bulkBody.push(JSON.stringify(doc));
  }

  if (bulkBody.length === 0) {
    return { indexed: 0, errors: [] };
  }

  try {
    const response = await fetch(`${opensearchUrl}/_bulk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-ndjson',
        'X-API-Key': opensearchApiKey,
      },
      body: bulkBody.join('\n') + '\n',
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      const errorText = await response.text();
      errors.push(`OpenSearch bulk request failed: ${response.status} - ${errorText}`);
      safeError(`[ERR] OpenSearch bulk indexing failed`, {
        status: response.status,
        error: errorText,
      });
    } else {
      const result = await response.json();
      indexed =
        result.items?.filter((item: Record<string, unknown>) => {
          const indexResult = item.index as Record<string, unknown>;
          return indexResult?.status === 201 || indexResult?.status === 200;
        }).length || 0;

      // Check for partial failures
      if (result.errors) {
        const failedItems = result.items?.filter((item: Record<string, unknown>) => {
          const indexResult = item.index as Record<string, unknown>;
          return indexResult?.error;
        });
        for (const item of failedItems || []) {
          const indexResult = item.index as Record<string, unknown>;
          const error = indexResult?.error as Record<string, unknown>;
          errors.push(`Failed to index document: ${error?.reason || 'Unknown error'}`);
        }
      }

      safeLog(`[STATS] OpenSearch indexed ${indexed}/${alerts.length} alerts to ${indexName}`);
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    errors.push(`OpenSearch indexing error: ${errorMsg}`);
    safeError(`[ERR] OpenSearch indexing exception`, error);
  }

  return { indexed, errors };
}

// ============================================================================
// JSON Sanitization for PostgreSQL JSONB
// ============================================================================

/**
 * Sanitize JSON data to remove invalid Unicode escape sequences
 * PostgreSQL JSONB doesn't support \u0000 (null byte) and some other sequences
 */
function sanitizeForPostgres(data: unknown): unknown {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    // Remove null bytes and other problematic Unicode sequences
    return data
      .replace(/\u0000/g, '') // Remove null bytes
      .replace(/\\u0000/g, '') // Remove escaped null bytes
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, ''); // Remove control characters except \t \n \r
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeForPostgres(item));
  }

  if (typeof data === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      const sanitizedKey = typeof key === 'string' ? (sanitizeForPostgres(key) as string) : key;
      sanitized[sanitizedKey] = sanitizeForPostgres(value);
    }
    return sanitized;
  }

  return data;
}

// ============================================================================
// SIEM Configuration Filtering - Asset controls what gets indexed
// ============================================================================

/**
 * Log level priority mapping (higher = more verbose)
 * Used to filter events based on siem_config.monitoring.log_level
 */
const LOG_LEVEL_PRIORITY: Record<string, number> = {
  critical: 1,
  error: 2,
  high: 2, // Map AISAC 'high' to error level
  warning: 3,
  medium: 3, // Map AISAC 'medium' to warning level
  info: 4,
  low: 4, // Map AISAC 'low' to info level
  debug: 5,
};

/**
 * Maps AISAC severity to log level for comparison.
 *
 * AISAC severity -> Log level (priority):
 *   critical -> critical (1)
 *   high     -> error    (2)
 *   medium   -> warning  (3)
 *   low      -> info     (4)
 *   info     -> info     (4)
 *
 * Both 'low' and 'info' map to log level 'info' so that
 * log_level:'info' shows everything, log_level:'warning' shows
 * medium+ only -- which is the intuitive behavior.
 */
function severityToLogLevel(severity: SeverityLevel): string {
  const mapping: Record<SeverityLevel, string> = {
    critical: 'critical',
    high: 'error',
    medium: 'warning',
    low: 'info',
    info: 'info',
  };
  return mapping[severity] || 'info';
}

/**
 * Filters alerts based on the asset's configured log_level.
 * Only alerts with severity >= configured level will pass through.
 *
 * @param alerts - Array of normalized alerts
 * @param configuredLogLevel - The minimum log level from siem_config.monitoring.log_level
 * @returns Filtered alerts that meet the severity threshold
 */
function filterByLogLevel(
  alerts: NormalizedAlert[],
  configuredLogLevel?: string
): { passed: NormalizedAlert[]; filtered: number } {
  // If no log_level configured, default to 'info' (allow most logs except debug)
  const minLevel = configuredLogLevel || 'info';
  const minPriority = LOG_LEVEL_PRIORITY[minLevel] || 4;

  const passed: NormalizedAlert[] = [];
  let filtered = 0;

  for (const alert of alerts) {
    const alertLogLevel = severityToLogLevel(alert.severity);
    const alertPriority = LOG_LEVEL_PRIORITY[alertLogLevel] || 4;

    // Alert passes if its priority is <= min priority (lower number = more severe)
    if (alertPriority <= minPriority) {
      passed.push(alert);
    } else {
      filtered++;
    }
  }

  return { passed, filtered };
}

/**
 * Filters alerts based on the asset's configured event_sources.
 * Only alerts from configured sources will pass through.
 *
 * @param alerts - Array of normalized alerts
 * @param configuredSources - Array of allowed source types from siem_config.monitoring.event_sources
 * @returns Filtered alerts from allowed sources
 */
function filterByEventSources(
  alerts: NormalizedAlert[],
  configuredSources?: string[]
): { passed: NormalizedAlert[]; filtered: number } {
  // If no event_sources configured or empty, allow all sources
  if (!configuredSources || configuredSources.length === 0) {
    return { passed: alerts, filtered: 0 };
  }

  // Normalize source names for comparison (lowercase, handle variations)
  const allowedSources = new Set(
    configuredSources.map(s => s.toLowerCase().replace(/[-_\s]/g, ''))
  );

  const passed: NormalizedAlert[] = [];
  let filtered = 0;

  for (const alert of alerts) {
    // Normalize alert source for comparison
    const alertSource = (alert.source || 'syslog').toLowerCase().replace(/[-_\s]/g, '');

    // Check if alert source matches any configured source
    // Also check partial matches (e.g., 'cisco_asa' matches 'cisco')
    const matches = Array.from(allowedSources).some(
      allowed => alertSource.includes(allowed) || allowed.includes(alertSource)
    );

    if (matches) {
      passed.push(alert);
    } else {
      filtered++;
    }
  }

  return { passed, filtered };
}

/**
 * Applies all SIEM configuration filters to alerts.
 * This is where the asset's siem_config controls what gets indexed.
 *
 * @param alerts - Array of normalized alerts
 * @param siemConfig - The asset's SIEM configuration
 * @returns Filtered alerts and statistics
 */
function applySIEMFilters(
  alerts: NormalizedAlert[],
  siemConfig?: SIEMConfig
): {
  passed: NormalizedAlert[];
  stats: {
    total: number;
    filteredByLogLevel: number;
    filteredByEventSources: number;
    passed: number;
  };
} {
  const stats = {
    total: alerts.length,
    filteredByLogLevel: 0,
    filteredByEventSources: 0,
    passed: 0,
  };

  // If SIEM is not configured or explicitly disabled, return empty
  if (!siemConfig || siemConfig.enabled === false) {
    stats.filteredByLogLevel = alerts.length;
    return { passed: [], stats };
  }
  // If log_collection is explicitly false AND siem_config.enabled is not true, skip
  // (When enabled=true, we treat log_collection as implicitly true)
  if (siemConfig.monitoring?.log_collection === false && !siemConfig.enabled) {
    stats.filteredByLogLevel = alerts.length;
    return { passed: [], stats };
  }

  let currentAlerts = alerts;

  // Step 1: Filter by log_level (use min_severity as fallback -- UI writes min_severity, not log_level)
  const effectiveLogLevel =
    siemConfig?.monitoring?.log_level || siemConfig?.monitoring?.min_severity;
  const logLevelResult = filterByLogLevel(currentAlerts, effectiveLogLevel);
  stats.filteredByLogLevel = logLevelResult.filtered;
  currentAlerts = logLevelResult.passed;

  // Step 2: Filter by event_sources
  const eventSourcesResult = filterByEventSources(
    currentAlerts,
    siemConfig?.monitoring?.event_sources
  );
  stats.filteredByEventSources = eventSourcesResult.filtered;
  currentAlerts = eventSourcesResult.passed;

  stats.passed = currentAlerts.length;

  return { passed: currentAlerts, stats };
}

/**
 * Severity threshold priority mapping (lower = more severe)
 */
const ALERTING_THRESHOLD_PRIORITY: Record<string, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
};

/**
 * Maps AISAC severity to alerting priority
 */
function severityToAlertingPriority(severity: SeverityLevel): number {
  const mapping: Record<SeverityLevel, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    info: 5, // Info never triggers alerts
  };
  return mapping[severity] || 5;
}

/**
 * Filters alerts that should trigger notifications based on severity_threshold.
 * Used by the alerting system to determine which alerts to notify about.
 *
 * @param alerts - Array of normalized alerts
 * @param alertingConfig - The asset's alerting configuration
 * @returns Alerts that meet or exceed the severity threshold
 */
function filterAlertsForNotification(
  alerts: NormalizedAlert[],
  alertingConfig?: SIEMConfig['alerting']
): { alertsToNotify: NormalizedAlert[]; count: number } {
  // If alerting is not enabled, don't notify
  if (!alertingConfig?.enabled) {
    return { alertsToNotify: [], count: 0 };
  }

  const threshold = alertingConfig.severity_threshold || 'high';
  const thresholdPriority = ALERTING_THRESHOLD_PRIORITY[threshold] || 2;

  const alertsToNotify: NormalizedAlert[] = [];

  for (const alert of alerts) {
    const alertPriority = severityToAlertingPriority(alert.severity);

    // Alert triggers notification if its priority is <= threshold priority
    // (lower priority number = more severe)
    if (alertPriority <= thresholdPriority) {
      alertsToNotify.push(alert);
    }
  }

  return { alertsToNotify, count: alertsToNotify.length };
}

/**
 * Filters alerts by the asset's min_severity threshold before DB insertion.
 * Only alerts whose severity meets or exceeds the threshold are kept.
 *
 * @param alerts - Array of normalized alerts
 * @param minSeverity - Minimum severity from siem_config.monitoring.min_severity
 * @returns Object with passed alerts and count of filtered alerts
 */
function filterByMinSeverity(
  alerts: NormalizedAlert[],
  minSeverity?: string
): { passed: NormalizedAlert[]; filtered: number } {
  if (!minSeverity) {
    return { passed: alerts, filtered: 0 };
  }

  const thresholdPriority = ALERTING_THRESHOLD_PRIORITY[minSeverity] ?? 4;
  const passed: NormalizedAlert[] = [];
  let filtered = 0;

  for (const alert of alerts) {
    const alertPriority = severityToAlertingPriority(alert.severity);
    if (alertPriority <= thresholdPriority) {
      passed.push(alert);
    } else {
      filtered++;
    }
  }

  return { passed, filtered };
}

// ============================================================================
// NOTE: PostgreSQL storage (external_alerts) has been removed.
// All SIEM events are stored exclusively in OpenSearch.
// Deduplication is handled by OpenSearch using document IDs based on dedup_key.
// ============================================================================

// ============================================================================
// Main Handler
// ============================================================================

/**
 * Decompress gzip data if Content-Encoding header indicates compression
 */
async function decompressIfNeeded(req: Request): Promise<{ body: string; wasCompressed: boolean }> {
  const contentEncoding = req.headers.get('content-encoding')?.toLowerCase() || '';
  const isGzip = contentEncoding.includes('gzip');

  if (!isGzip) {
    // Not compressed - read as text directly
    const text = await req.text();
    return { body: text, wasCompressed: false };
  }

  // Decompress gzip data
  try {
    const compressedData = await req.arrayBuffer();
    const decompressedStream = new DecompressionStream('gzip');
    const writer = decompressedStream.writable.getWriter();
    writer.write(new Uint8Array(compressedData));
    writer.close();

    const reader = decompressedStream.readable.getReader();
    const chunks: Uint8Array[] = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    // Combine chunks and decode as UTF-8
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    const text = new TextDecoder('utf-8').decode(combined);
    safeLog(
      `[PKG] Decompressed gzip data: ${compressedData.byteLength} bytes -> ${text.length} chars`
    );
    return { body: text, wasCompressed: true };
  } catch (error) {
    safeError('[ERR] Gzip decompression failed', error);
    throw new Error('Failed to decompress gzip data');
  }
}

/**
 * Check if data appears to be binary/compressed based on content
 */
function isBinaryData(data: string): boolean {
  // Check first 100 chars for non-printable characters (common in binary data)
  const sample = data.substring(0, 100);
  let nonPrintableCount = 0;

  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    // Non-printable characters (excluding common whitespace)
    if ((code < 32 || code > 126) && code !== 9 && code !== 10 && code !== 13) {
      nonPrintableCount++;
    }
  }

  // If more than 20% non-printable, likely binary
  return nonPrintableCount > sample.length * 0.2;
}

serve(async (req: Request) => {
  // CRITICAL FIX: Validate environment variables before processing
  const envError = validateSupabaseEnv();
  if (envError) {
    return envError;
  }

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: getCorsHeaders(req) });
  }

  // Only accept POST requests
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Método no permitido. Use POST.' }), {
      status: 405,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  try {
    // Initialize Supabase client with service role
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

    const contentType = req.headers.get('content-type') || '';
    const contentEncoding = req.headers.get('content-encoding') || '';
    let messages: string[] = [];
    let validatedTenantId: string;
    let assetId: string | null = null;
    let source: string = 'rsyslog';
    let siemEnabled: boolean = false; // Track if SIEM indexing is enabled for this asset
    let siemConfig: SIEMConfig | undefined; // Full SIEM config for behavior control

    safeLog(
      `[IN] Incoming request: Content-Type=${contentType}, Content-Encoding=${contentEncoding}`
    );

    // ========================================================================
    // AUTHENTICATION: Check for API Key or JWT
    // ========================================================================
    const bearerToken = extractBearerToken(req);

    if (!bearerToken) {
      return new Response(
        JSON.stringify({
          error: 'Token de autenticación requerido',
          details: 'Proporcione X-API-Key: <aisac_api_key> o Authorization: Bearer <token>',
        }),
        {
          status: 401,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // Check if it's an AISAC API Key (format: aisac_xxx)
    const useApiKeyAuth = isAisacApiKey(bearerToken);

    if (useApiKeyAuth) {
      // ======================================================================
      // API KEY AUTHENTICATION (for AISAC Agents)
      // ======================================================================
      safeLog('[KEY] Using API Key authentication');

      const apiKeyValidation = await validateAssetApiKey(supabase, bearerToken);

      if (!apiKeyValidation.valid || !apiKeyValidation.tenantId) {
        safeLog(`[ERR] API Key validation failed: ${apiKeyValidation.error}`);
        return new Response(
          JSON.stringify({
            error: 'API Key inválida o asset no configurado',
            details: apiKeyValidation.error || 'El asset no está habilitado para ingesta de logs',
          }),
          {
            status: 401,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }

      validatedTenantId = apiKeyValidation.tenantId;
      assetId = apiKeyValidation.assetId || null;
      siemEnabled = apiKeyValidation.siemEnabled || false;
      siemConfig = apiKeyValidation.siemConfig;

      // Log configuration details for debugging
      const logLevel = siemConfig?.monitoring?.log_level || 'default';
      const eventSources = siemConfig?.monitoring?.event_sources?.length || 0;
      const minSev = siemConfig?.monitoring?.min_severity || 'none';
      safeLog(
        `[OK] API Key valid for asset: ${apiKeyValidation.assetName} (tenant: ${validatedTenantId}, SIEM: ${siemEnabled ? 'enabled' : 'disabled'}, log_level: ${logLevel}, event_sources: ${eventSources}, min_severity: ${minSev})`
      );

      // Parse request body (tenant_id NOT required in payload for API Key auth)
      // Handle compressed data if Content-Encoding: gzip
      if (contentType.includes('application/json')) {
        let body: unknown;
        try {
          // Check for gzip compression
          const { body: rawBody, wasCompressed } = await decompressIfNeeded(req);

          if (wasCompressed) {
            safeLog(`[PKG] Decompressed JSON body from gzip`);
          }

          // Check if the data looks like binary (failed decompression or wrong format)
          if (isBinaryData(rawBody)) {
            safeLog(
              `[WARN] Detected binary data after decompression - may need different handling`
            );
            // Try to interpret as raw syslog lines
            const lines = rawBody.split('\n').filter((l: string) => l.trim().length > 0);
            if (lines.length > 0) {
              messages = lines;
              source = 'binary_syslog';
            }
          } else {
            body = JSON.parse(rawBody);
          }
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          safeError(`[ERR] Failed to parse request body: ${errorMsg}`, error);
          return new Response(
            JSON.stringify({
              error: 'Cuerpo de solicitud inválido',
              details: `El JSON proporcionado no es válido: ${errorMsg}`,
            }),
            {
              status: 400,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        // If we haven't already extracted messages from binary data
        if (messages.length === 0 && body) {
          const validation = SyslogApiKeyBatchSchema.safeParse(body);
          if (!validation.success) {
            const errors = validation.error.errors.map(err => ({
              field: err.path.join('.'),
              message: err.message,
            }));

            return new Response(
              JSON.stringify({
                error: 'Validación de datos fallida',
                details: 'Los datos proporcionados no cumplen con el esquema requerido',
                validation_errors: errors,
              }),
              {
                status: 400,
                headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
              }
            );
          }

          source = validation.data.source;
          messages = validation.data.messages;
        }
      } else {
        // Raw syslog format - also handle compression
        const { body: rawText, wasCompressed } = await decompressIfNeeded(req);

        if (wasCompressed) {
          safeLog(`[PKG] Decompressed raw syslog from gzip`);
        }

        if (!rawText || rawText.trim().length === 0) {
          return new Response(
            JSON.stringify({
              error: 'Cuerpo de solicitud vacío',
              details: 'Debe proporcionar al menos un mensaje syslog',
            }),
            {
              status: 400,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        // Check if data looks binary even after decompression
        if (isBinaryData(rawText)) {
          safeLog(`[WARN] Received binary data - attempting to extract readable content`);
          // Extract any readable portions
          const readableText = rawText.replace(/[^\x20-\x7E\n\r\t]/g, ' ').trim();
          if (readableText.length > 10) {
            messages = readableText.split('\n').filter((l: string) => l.trim().length > 0);
          } else {
            return new Response(
              JSON.stringify({
                error: 'Datos binarios no procesables',
                details:
                  'Los datos recibidos parecen ser binarios y no se pueden interpretar como texto',
              }),
              {
                status: 400,
                headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
              }
            );
          }
        } else {
          // Normal text - split into lines if multiple
          messages = rawText.split('\n').filter((l: string) => l.trim().length > 0);
          if (messages.length === 0) {
            messages = [rawText];
          }
        }
      }
    } else {
      // ======================================================================
      // JWT AUTHENTICATION (legacy, backwards compatible)
      // ======================================================================
      safeLog('[AUTH] Using JWT authentication');

      // Parse request based on content type - handle compression
      if (contentType.includes('application/json')) {
        // JSON batch format
        let body: unknown;
        try {
          const { body: rawBody, wasCompressed } = await decompressIfNeeded(req);
          if (wasCompressed) {
            safeLog(`[PKG] Decompressed JSON body from gzip (JWT auth)`);
          }
          body = JSON.parse(rawBody);
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          return new Response(
            JSON.stringify({
              error: 'Cuerpo de solicitud inválido',
              details: `El JSON proporcionado no es válido: ${errorMsg}`,
            }),
            {
              status: 400,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        const validation = SyslogBatchSchema.safeParse(body);
        if (!validation.success) {
          const errors = validation.error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message,
          }));

          return new Response(
            JSON.stringify({
              error: 'Validación de datos fallida',
              details: 'Los datos proporcionados no cumplen con el esquema requerido',
              validation_errors: errors,
            }),
            {
              status: 400,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        const tenantIdFromBody = validation.data.tenant_id;
        const assetIdFromBody = validation.data.asset_id;
        source = validation.data.source;
        messages = validation.data.messages;

        // Authenticate and validate tenant access
        const authResult = await authenticateRequest(req, supabase, tenantIdFromBody);
        if ('error' in authResult) {
          return createAuthErrorResponse(authResult);
        }
        validatedTenantId = authResult.tenantId;

        // ====================================================================
        // MANDATORY: Validate asset belongs to tenant and get SIEM config
        // This ensures multi-asset isolation and proper SIEM behavior
        // ====================================================================
        const assetValidation = await validateAssetById(
          supabase,
          assetIdFromBody,
          validatedTenantId
        );
        if (!assetValidation.valid) {
          safeLog(`[ERR] Asset validation failed for ${assetIdFromBody}: ${assetValidation.error}`);
          return new Response(
            JSON.stringify({
              error: 'Asset inválido o no autorizado',
              details: assetValidation.error || 'El asset no está habilitado para ingesta de logs',
            }),
            {
              status: 403,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        // Set asset context for SIEM processing
        assetId = assetIdFromBody;
        siemEnabled = assetValidation.siemEnabled;
        siemConfig = assetValidation.siemConfig;

        safeLog(
          `[OK] JWT auth valid for asset: ${assetValidation.assetName} (tenant: ${validatedTenantId}, SIEM: ${siemEnabled ? 'enabled' : 'disabled'})`
        );
      } else {
        // Raw syslog format (text/plain) - handle compression
        const { body: rawText, wasCompressed } = await decompressIfNeeded(req);
        if (wasCompressed) {
          safeLog(`[PKG] Decompressed raw syslog from gzip (JWT auth)`);
        }

        if (!rawText || rawText.trim().length === 0) {
          return new Response(
            JSON.stringify({
              error: 'Cuerpo de solicitud vacío',
              details: 'Debe proporcionar al menos un mensaje syslog',
            }),
            {
              status: 400,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        // Split into lines if multiple
        messages = rawText.split('\n').filter((l: string) => l.trim().length > 0);
        if (messages.length === 0) {
          messages = [rawText];
        }

        // For raw format, extract tenant_id and asset_id from query params
        // MANDATORY: Both are required for multi-tenant/multi-asset isolation
        const url = new URL(req.url);
        const queryTenantId = url.searchParams.get('tenant_id');
        const queryAssetId = url.searchParams.get('asset_id');

        if (!queryTenantId) {
          return new Response(
            JSON.stringify({
              error: 'tenant_id requerido',
              details:
                'Para formato raw syslog, proporcione tenant_id como parámetro de consulta. Ejemplo: ?tenant_id=<uuid>&asset_id=<uuid>',
            }),
            {
              status: 400,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        if (!queryAssetId) {
          return new Response(
            JSON.stringify({
              error: 'asset_id requerido',
              details:
                'Para formato raw syslog, proporcione asset_id como parámetro de consulta. Ejemplo: ?tenant_id=<uuid>&asset_id=<uuid>',
            }),
            {
              status: 400,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        // Authenticate and validate tenant access
        const authResult = await authenticateRequest(req, supabase, queryTenantId);
        if ('error' in authResult) {
          return createAuthErrorResponse(authResult);
        }
        validatedTenantId = authResult.tenantId;

        // ====================================================================
        // MANDATORY: Validate asset belongs to tenant and get SIEM config
        // ====================================================================
        const assetValidation = await validateAssetById(supabase, queryAssetId, validatedTenantId);
        if (!assetValidation.valid) {
          safeLog(`[ERR] Asset validation failed for ${queryAssetId}: ${assetValidation.error}`);
          return new Response(
            JSON.stringify({
              error: 'Asset inválido o no autorizado',
              details: assetValidation.error || 'El asset no está habilitado para ingesta de logs',
            }),
            {
              status: 403,
              headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
            }
          );
        }

        // Set asset context for SIEM processing
        assetId = queryAssetId;
        siemEnabled = assetValidation.siemEnabled;
        siemConfig = assetValidation.siemConfig;

        safeLog(
          `[OK] JWT auth (raw format) valid for asset: ${assetValidation.assetName} (tenant: ${validatedTenantId}, SIEM: ${siemEnabled ? 'enabled' : 'disabled'})`
        );
      }
    }

    // ========================================================================
    // SECURITY CHECK: Ensure we always have both tenant_id and asset_id
    // This is critical for multi-tenant/multi-asset data isolation
    // ========================================================================
    if (!validatedTenantId || !assetId) {
      safeLog(
        `[ERR] Security violation: Missing tenant_id (${validatedTenantId}) or asset_id (${assetId})`
      );
      return new Response(
        JSON.stringify({
          error: 'Configuración incompleta',
          details:
            'Tanto tenant_id como asset_id son requeridos para la ingesta de logs. Configure estos valores en el agente.',
        }),
        {
          status: 400,
          headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
        }
      );
    }

    // Check rate limit
    const rateCheck = checkRateLimit(validatedTenantId, messages.length);
    if (!rateCheck.allowed) {
      safeLog(`[WARN] Rate limit exceeded for tenant ${validatedTenantId}`);
      return new Response(
        JSON.stringify({
          error: 'Límite de tasa excedido',
          details:
            'Ha superado el límite de 500 mensajes por minuto. Intente nuevamente más tarde.',
          retry_after_seconds: 60,
        }),
        {
          status: 429,
          headers: {
            ...getCorsHeaders(req),
            'Content-Type': 'application/json',
            'Retry-After': '60',
          },
        }
      );
    }

    // Check SIEM GB/day quota before ingesting
    const { data: siemQuota } = await supabase
      .from('usage_quotas')
      .select('siem_gb_used, siem_gb_limit')
      .eq('tenant_id', validatedTenantId)
      .maybeSingle();

    if (siemQuota && siemQuota.siem_gb_limit > 0 && siemQuota.siem_gb_limit < 99999) {
      if (siemQuota.siem_gb_used >= siemQuota.siem_gb_limit) {
        safeLog(
          `[WARN] SIEM GB/day quota exceeded for tenant ${validatedTenantId}: ${siemQuota.siem_gb_used}/${siemQuota.siem_gb_limit} GB`
        );
        return new Response(
          JSON.stringify({
            error: 'SIEM ingestion quota exceeded',
            details: `Daily SIEM ingestion limit of ${siemQuota.siem_gb_limit} GB reached. Upgrade your plan for more capacity.`,
            used_gb: siemQuota.siem_gb_used,
            limit_gb: siemQuota.siem_gb_limit,
          }),
          {
            status: 429,
            headers: {
              ...getCorsHeaders(req),
              'Content-Type': 'application/json',
              'Retry-After': '3600',
            },
          }
        );
      }
    }

    safeLog(`[IN] Processing ${messages.length} syslog message(s) for tenant ${validatedTenantId}`);

    // Process messages
    const processedAlerts: NormalizedAlert[] = [];
    const errors: Array<{ message: string; error: string }> = [];
    let telemetryFiltered = 0; // Count of Suricata telemetry events skipped

    for (const message of messages) {
      try {
        // Parse syslog message
        const parsed = parseSyslogMessage(message);

        let normalized: NormalizedAlert;

        // Special handling for Suricata: extract EVE JSON for structured parsing
        if (parsed.source === 'ids_suricata') {
          const eve = tryExtractSuricataEve(parsed.message) || tryExtractSuricataEve(parsed.raw);
          if (eve) {
            // Filter out telemetry events (dns, tls, flow, http, stats, etc.)
            // These are protocol metadata, NOT security alerts - skip at ingestion time
            const eventType = String(eve.event_type || 'unknown');
            if (SURICATA_TELEMETRY_EVENT_TYPES.has(eventType)) {
              // Skip telemetry - don't normalize or ingest
              telemetryFiltered++;
              continue;
            }
            normalized = normalizeSuricataEve(eve, parsed.raw);
          } else {
            // No EVE JSON found -- fall back to generic syslog normalization
            normalized = normalizeSyslogToAlert(parsed);
          }
        } else if (parsed.source === 'wazuh') {
          // Special handling for Wazuh/OSSEC: extract Level and Rule ID for proper severity mapping
          // Wazuh Level 0-15 maps differently than syslog severity 0-7
          const wazuhData = tryExtractWazuhData(parsed.message) || tryExtractWazuhData(parsed.raw);
          if (wazuhData) {
            normalized = normalizeWazuhAlert(parsed, wazuhData);
            safeLog(
              `[SEARCH] Wazuh alert parsed: Rule ${wazuhData.ruleId}, Level ${wazuhData.level} -> ${normalized.severity}`
            );
          } else {
            // Could not extract Wazuh data -- fall back to generic syslog normalization
            safeLog(`[WARN] Wazuh alert detected but could not extract Rule/Level, using fallback`);
            normalized = normalizeSyslogToAlert(parsed);
          }

          // ================================================================
          // WAZUH ENRICHMENT: Extract agent info and network data from
          // the full JSON payload (not in wazuhData which only has
          // rule/level/description).
          // ================================================================
          const agentInfo =
            extractWazuhAgentInfo(parsed.message) || extractWazuhAgentInfo(parsed.raw);
          if (agentInfo?.name) {
            normalized.wazuh_agent_name = agentInfo.name;
            normalized.wazuh_agent_id = agentInfo.id;
            normalized.wazuh_agent_ip = agentInfo.ip || undefined;
          }

          // Fix hostname and extract IPs from full Wazuh JSON
          const networkInfo =
            extractWazuhNetworkInfo(parsed.message) || extractWazuhNetworkInfo(parsed.raw);
          if (networkInfo) {
            // Fix hostname: use agent.name from JSON instead of syslog prefix "wazuh:"
            if (networkInfo.hostname) {
              if (normalized.raw_data && typeof normalized.raw_data === 'object') {
                (normalized.raw_data as Record<string, unknown>).hostname = networkInfo.hostname;
              }
            }

            // Enrich IPs from JSON (data.srcip, data.win.eventdata.ipAddress, agent.ip)
            if (networkInfo.srcIp) {
              normalized.src_ip = networkInfo.srcIp;
              if (!normalized.entities.ips) {
                normalized.entities.ips = [];
              }
              if (!normalized.entities.ips.includes(networkInfo.srcIp)) {
                normalized.entities.ips.unshift(networkInfo.srcIp);
              }
            }
            if (networkInfo.dstIp) {
              normalized.dest_ip = networkInfo.dstIp;
              if (!normalized.entities.ips) {
                normalized.entities.ips = [];
              }
              if (!normalized.entities.ips.includes(networkInfo.dstIp)) {
                normalized.entities.ips.push(networkInfo.dstIp);
              }
            }
            if (networkInfo.srcPort) {
              normalized.src_port = networkInfo.srcPort;
              if (!normalized.entities.ports) {
                normalized.entities.ports = [];
              }
              if (!normalized.entities.ports.includes(networkInfo.srcPort)) {
                normalized.entities.ports.push(networkInfo.srcPort);
              }
            }
          }
        } else {
          // All other sources: generic syslog normalization
          normalized = normalizeSyslogToAlert(parsed);
        }

        processedAlerts.push(normalized);
      } catch (error) {
        // Don't fail entire batch - record error and continue
        const errorMsg = error instanceof Error ? error.message : 'Error desconocido';
        errors.push({ message: message.substring(0, 100), error: errorMsg });
        safeError(`[WARN] Failed to process message`, error);
      }
    }

    // Log telemetry filtering statistics
    if (telemetryFiltered > 0) {
      safeLog(
        `[MUTE] Suricata telemetry filter: ${telemetryFiltered} event(s) skipped (dns/tls/flow/http/stats/etc.)`
      );
    }

    // Ingest alerts (batch for performance)
    let alertIds: string[] = [];
    let siemIndexed = 0;
    let siemErrors: string[] = [];
    let siemFilterStats:
      | {
          total: number;
          filteredByLogLevel: number;
          filteredByEventSources: number;
          passed: number;
        }
      | undefined;
    let siemAlertingStats:
      | {
          enabled: boolean;
          threshold: string;
          matched: number;
          notified: number;
          channels: string[];
          errors: string[];
        }
      | undefined;
    let siemCorrelationStats:
      | {
          enabled: boolean;
          triggered: boolean;
          rule_ids: string[];
          alerts_for_correlation: number;
          error?: string;
        }
      | undefined;

    // ====================================================================
    // Apply min_severity filter BEFORE DB insertion
    // Drops alerts below the asset's configured threshold
    // ====================================================================
    const minSeverity = siemConfig?.monitoring?.min_severity;
    let minSeverityFiltered = 0;
    let alertsToIngest = processedAlerts;

    if (minSeverity && processedAlerts.length > 0) {
      const severityResult = filterByMinSeverity(processedAlerts, minSeverity);
      alertsToIngest = severityResult.passed;
      minSeverityFiltered = severityResult.filtered;

      if (minSeverityFiltered > 0) {
        safeLog(
          `[SEARCH] min_severity filter (${minSeverity}): ${minSeverityFiltered} alert(s) dropped, ${alertsToIngest.length} passed`
        );
      }
    }

    if (alertsToIngest.length > 0) {
      try {
        // ====================================================================
        // Storage: OpenSearch (primary) + PostgreSQL external_alerts (secondary)
        // OpenSearch for SIEM dashboard aggregations and search.
        // PostgreSQL for correlation engine, SOAR, and NIS2 workflows.
        // ====================================================================

        // Generate IDs for response (alerts stored only in OpenSearch)
        alertIds = alertsToIngest.map(() => crypto.randomUUID());

        // Hoisted: alertsByAsset is populated by SIEM agent routing and reused
        // by the PostgreSQL insert below.
        let alertsByAsset = new Map<string, NormalizedAlert[]>();

        // Index to OpenSearch for SIEM dashboard visibility ONLY if SIEM is enabled for this asset
        if (siemEnabled) {
          // ====================================================================
          // Apply SIEM Configuration Filters
          // The asset's siem_config controls what gets indexed
          // ====================================================================
          const filterResult = applySIEMFilters(alertsToIngest, siemConfig);
          siemFilterStats = filterResult.stats;

          if (filterResult.passed.length > 0) {
            // ==============================================================
            // WAZUH AGENT ROUTING: Resolve real asset_id per alert
            //
            // When alerts arrive from a Wazuh Manager (collector), each alert
            // may belong to a different agent/host. We group alerts by their
            // resolved asset_id and index each group separately so they appear
            // under the correct asset in the SIEM dashboard.
            //
            // Alerts without agent.name or without a matching asset fall back
            // to the collector's asset_id (original behavior).
            // ==============================================================
            alertsByAsset = new Map<string, NormalizedAlert[]>();
            let routedCount = 0;

            for (const alert of filterResult.passed) {
              let targetAssetId: string = assetId!; // default: collector

              if (alert.wazuh_agent_name) {
                const resolved = await resolveWazuhAgentAsset(
                  supabase,
                  validatedTenantId,
                  alert.wazuh_agent_name,
                  alert.wazuh_agent_ip
                );

                if (resolved && resolved.siemEnabled) {
                  targetAssetId = resolved.assetId;
                  if (targetAssetId !== assetId) {
                    routedCount++;
                  }
                }
                // If resolved but SIEM disabled, or no match: fallback to collector
              }

              const group = alertsByAsset.get(targetAssetId);
              if (group) {
                group.push(alert);
              } else {
                alertsByAsset.set(targetAssetId, [alert]);
              }
            }

            if (routedCount > 0) {
              safeLog(
                `[ROUTE] Wazuh agent routing: ${routedCount} alert(s) routed to real assets, ` +
                  `${filterResult.passed.length - routedCount} kept on collector. ` +
                  `Groups: ${alertsByAsset.size}`
              );
            }

            // Index each asset group separately
            for (const [targetId, alerts] of alertsByAsset) {
              const opensearchResult = await indexToOpenSearch(alerts, validatedTenantId, targetId);
              siemIndexed += opensearchResult.indexed;
              siemErrors.push(...opensearchResult.errors);
            }

            if (siemIndexed > 0) {
              safeLog(
                `[OK] Indexed ${siemIndexed}/${alertsToIngest.length} alert(s) to OpenSearch for SIEM`
              );
            }
          }

          // Log filtering statistics
          if (
            siemFilterStats.filteredByLogLevel > 0 ||
            siemFilterStats.filteredByEventSources > 0
          ) {
            safeLog(
              `[SEARCH] SIEM Filters applied: ${siemFilterStats.filteredByLogLevel} filtered by log_level, ` +
                `${siemFilterStats.filteredByEventSources} filtered by event_sources, ` +
                `${siemFilterStats.passed} passed`
            );
          }

          if (siemErrors.length > 0) {
            safeLog(`[WARN] OpenSearch indexing errors: ${siemErrors.join(', ')}`);
          }

          // ====================================================================
          // Process Alerting - Check if alerts should trigger notifications
          // Based on siem_config.alerting.severity_threshold
          // ====================================================================
          if (siemConfig?.alerting?.enabled && assetId) {
            const alertingResult = filterAlertsForNotification(
              filterResult.passed,
              siemConfig.alerting
            );

            siemAlertingStats = {
              enabled: true,
              threshold: siemConfig.alerting.severity_threshold || 'high',
              matched: alertingResult.count,
              notified: alertingResult.count, // All matching alerts are "notified" (logged to OpenSearch)
              channels: siemConfig.alerting.alert_channels || [],
              errors: [],
            };

            if (alertingResult.count > 0) {
              safeLog(
                `[BELL] Alerting: ${alertingResult.count} alerts matched notification threshold ` +
                  `(threshold: ${siemConfig.alerting.severity_threshold || 'high'})`
              );
              // Note: Actual notification delivery (email, webhook, etc.) should be handled
              // by a separate notification service that reads from OpenSearch
            }
          } else if (siemConfig?.alerting?.enabled === false) {
            siemAlertingStats = {
              enabled: false,
              threshold: siemConfig?.alerting?.severity_threshold || 'high',
              matched: 0,
              notified: 0,
              channels: [],
              errors: [],
            };
          }

          // ====================================================================
          // Process Correlation - Trigger correlation engine if enabled
          // Based on siem_config.correlation.enabled and correlation.rule_ids
          // ====================================================================
          if (siemConfig?.correlation?.enabled && assetId && alertIds.length > 0) {
            const ruleIds = siemConfig.correlation.rule_ids || [];

            siemCorrelationStats = {
              enabled: true,
              triggered: false,
              rule_ids: ruleIds,
              alerts_for_correlation: alertIds.length,
            };

            // Trigger real-time correlation if there are specific rules configured
            // This calls the correlation-engine edge function asynchronously
            if (ruleIds.length > 0) {
              try {
                // Note: The correlation metadata is stored in OpenSearch documents
                // We trigger the correlation engine to process these alerts immediately
                // instead of waiting for the periodic run
                const correlationPayload = {
                  tenant_id: validatedTenantId,
                  asset_id: assetId,
                  alert_ids: alertIds,
                  rule_ids: ruleIds,
                  trigger: 'real_time',
                };

                // Get the Supabase URL for internal function call
                const supabaseUrl = Deno.env.get('SUPABASE_URL');
                const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

                if (supabaseUrl && supabaseServiceKey) {
                  // Fire-and-forget async call to correlation engine
                  // We don't await this to avoid slowing down the ingestion response
                  fetch(`${supabaseUrl}/functions/v1/correlation-engine`, {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      Authorization: `Bearer ${supabaseServiceKey}`,
                    },
                    body: JSON.stringify(correlationPayload),
                  })
                    .then(response => {
                      if (response.ok) {
                        safeLog(
                          `[LINK] Correlation engine triggered for ${alertIds.length} alerts with ${ruleIds.length} rules`
                        );
                      } else {
                        safeLog(`[WARN] Correlation engine returned status ${response.status}`);
                      }
                    })
                    .catch(err => {
                      safeLog(`[WARN] Failed to trigger correlation engine: ${err.message}`);
                    });

                  siemCorrelationStats.triggered = true;
                  safeLog(
                    `[LINK] Correlation: Triggering engine for ${alertIds.length} alerts with rules: [${ruleIds.slice(0, 3).join(', ')}${ruleIds.length > 3 ? '...' : ''}]`
                  );
                } else {
                  siemCorrelationStats.error =
                    'Missing Supabase configuration for correlation trigger';
                  safeLog(
                    `[WARN] Correlation: Cannot trigger engine - missing Supabase configuration`
                  );
                }
              } catch (correlationError) {
                const errMsg =
                  correlationError instanceof Error ? correlationError.message : 'Unknown error';
                siemCorrelationStats.error = errMsg;
                safeLog(`[WARN] Correlation trigger error: ${errMsg}`);
              }
            } else {
              safeLog(
                `[LINK] Correlation: Enabled but no specific rules configured - will process in periodic run`
              );
            }
          } else if (siemConfig?.correlation?.enabled === false) {
            siemCorrelationStats = {
              enabled: false,
              triggered: false,
              rule_ids: [],
              alerts_for_correlation: 0,
            };
          }
        } else {
          safeLog(`[SKIP] SIEM indexing skipped - SIEM is disabled for this asset`);
        }

        // ==================================================================
        // PostgreSQL Storage: Batch insert into external_alerts
        // This ensures alerts are visible in correlation engine, SOAR,
        // NIS2 workflows, and the SIEM dashboard's external_alerts source.
        // Uses the same agent routing results from OpenSearch indexing.
        // ==================================================================
        try {
          // Build rows with resolved asset_id per alert
          const pgRows: Record<string, unknown>[] = [];

          // If SIEM was enabled, alertsByAsset has the resolved asset_ids
          // Otherwise, use the default assetId for all alerts
          if (alertsByAsset.size > 0) {
            for (const [targetId, alerts] of alertsByAsset) {
              for (const alert of alerts) {
                const normalizedTitle = alert.title.toLowerCase().replace(/[^a-z0-9]+/g, '_');
                const agentPart = alert.wazuh_agent_name
                  ? `_${alert.wazuh_agent_name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`
                  : '';
                const dedupKey = `${validatedTenantId}_${targetId}${agentPart}_${alert.source}_${alert.severity}_${normalizedTitle}`;

                pgRows.push({
                  tenant_id: validatedTenantId,
                  asset_id: targetId,
                  source: alert.source,
                  severity: alert.severity,
                  type: alert.type,
                  title: alert.title,
                  description: alert.description || null,
                  entities: alert.entities || {},
                  raw_data: alert.raw_data || {},
                  status: 'new',
                  dedup_key: dedupKey,
                  occurrence_count: 1,
                });
              }
            }
          } else {
            // SIEM disabled or no agent routing — use default assetId
            for (const alert of alertsToIngest) {
              const normalizedTitle = alert.title.toLowerCase().replace(/[^a-z0-9]+/g, '_');
              const agentPart = alert.wazuh_agent_name
                ? `_${alert.wazuh_agent_name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`
                : '';
              const dedupKey = `${validatedTenantId}_${assetId}${agentPart}_${alert.source}_${alert.severity}_${normalizedTitle}`;

              pgRows.push({
                tenant_id: validatedTenantId,
                asset_id: assetId,
                source: alert.source,
                severity: alert.severity,
                type: alert.type,
                title: alert.title,
                description: alert.description || null,
                entities: alert.entities || {},
                raw_data: alert.raw_data || {},
                status: 'new',
                dedup_key: dedupKey,
                occurrence_count: 1,
              });
            }
          }

          if (pgRows.length > 0) {
            // Filter out duplicates: check which dedup_keys already exist (24h window)
            const dedupKeys = pgRows.map(r => r.dedup_key as string).filter(Boolean);
            const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
            let existingKeys = new Set<string>();

            if (dedupKeys.length > 0) {
              const { data: existing } = await supabase
                .from('external_alerts')
                .select('dedup_key')
                .eq('tenant_id', validatedTenantId)
                .in('dedup_key', dedupKeys)
                .gte('created_at', cutoff);

              if (existing) {
                existingKeys = new Set(existing.map((e: { dedup_key: string }) => e.dedup_key));
              }
            }

            // Only insert alerts whose dedup_key doesn't already exist
            const newRows = pgRows.filter(r => !existingKeys.has(r.dedup_key as string));
            const skippedCount = pgRows.length - newRows.length;

            if (newRows.length > 0) {
              const { error: insertError } = await supabase.from('external_alerts').insert(newRows);

              if (insertError) {
                safeLog(`[WARN] PostgreSQL insert failed: ${insertError.message}`);
              } else {
                safeLog(
                  `[OK] Inserted ${newRows.length} alert(s) into external_alerts` +
                    (skippedCount > 0 ? ` (${skippedCount} dedup skipped)` : '')
                );
              }
            } else if (skippedCount > 0) {
              safeLog(`[OK] All ${skippedCount} alert(s) already in external_alerts (dedup)`);
            }
          }
        } catch (pgError) {
          // Non-fatal: OpenSearch is the primary store, PostgreSQL is secondary
          const errMsg = pgError instanceof Error ? pgError.message : 'Unknown error';
          safeLog(`[WARN] external_alerts insert failed (non-fatal): ${errMsg}`);
        }

        // Update asset heartbeat if using API Key auth
        if (assetId) {
          await supabase
            .from('monitored_assets')
            .update({
              agent_last_seen: new Date().toISOString(),
              last_heartbeat: new Date().toISOString(),
              last_event_at: new Date().toISOString(),
              status: 'online',
              updated_at: new Date().toISOString(),
            })
            .eq('id', assetId);
          safeLog(`[STATS] Updated heartbeat for asset ${assetId}`);
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Error desconocido';
        safeError('[ERR] Batch ingestion failed', error);
        return new Response(
          JSON.stringify({
            error: 'Error al guardar alertas',
            details: errorMsg,
          }),
          {
            status: 500,
            headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
          }
        );
      }
    }

    // Return success response
    const response: Record<string, unknown> = {
      status: 'success',
      processed: processedAlerts.length,
      ingested: alertsToIngest.length,
      filtered_by_telemetry: telemetryFiltered, // Suricata dns/tls/flow/http/stats skipped at ingestion
      filtered_by_min_severity: minSeverityFiltered,
      failed: errors.length,
      alert_ids: alertIds,
      rate_limit_remaining: rateCheck.remaining,
      message: `Procesados ${processedAlerts.length} mensaje(s) correctamente`,
      // SIEM indexing info with filtering and alerting statistics
      siem: {
        enabled: siemEnabled,
        indexed: siemIndexed,
        skipped: !siemEnabled,
        // Include filtering stats when SIEM is enabled
        filtering:
          siemEnabled && siemFilterStats
            ? {
                total: siemFilterStats.total,
                filtered_by_log_level: siemFilterStats.filteredByLogLevel,
                filtered_by_event_sources: siemFilterStats.filteredByEventSources,
                passed: siemFilterStats.passed,
                config: {
                  log_level: siemConfig?.monitoring?.log_level || 'info',
                  event_sources: siemConfig?.monitoring?.event_sources || [],
                  min_severity: minSeverity || null,
                },
              }
            : undefined,
        // Include alerting stats when alerting is configured
        alerting: siemAlertingStats
          ? {
              enabled: siemAlertingStats.enabled,
              threshold: siemAlertingStats.threshold,
              matched: siemAlertingStats.matched,
              notified: siemAlertingStats.notified,
              channels: siemAlertingStats.channels,
              errors: siemAlertingStats.errors.length > 0 ? siemAlertingStats.errors : undefined,
            }
          : undefined,
        // Include correlation stats when correlation is configured
        correlation: siemCorrelationStats
          ? {
              enabled: siemCorrelationStats.enabled,
              triggered: siemCorrelationStats.triggered,
              rule_ids: siemCorrelationStats.rule_ids,
              alerts_for_correlation: siemCorrelationStats.alerts_for_correlation,
              error: siemCorrelationStats.error,
            }
          : undefined,
        errors: siemErrors.length > 0 ? siemErrors : undefined,
      },
    };

    // Include asset info if using API Key auth
    if (assetId) {
      response.asset_id = assetId;
    }

    if (errors.length > 0) {
      response.errors = errors;
      response.message = `Procesados ${processedAlerts.length} de ${messages.length} mensaje(s). ${errors.length} fallo(s).`;
    }

    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
    });
  } catch (error) {
    safeError('[ERR] Syslog ingestion error', error);

    const errorMessage = error instanceof Error ? error.message : 'Error desconocido';

    return new Response(
      JSON.stringify({
        error: 'Error interno del servidor',
        details: errorMessage,
        message: 'Por favor, intente nuevamente o contacte con soporte si el problema persiste',
      }),
      {
        status: 500,
        headers: { ...getCorsHeaders(req), 'Content-Type': 'application/json' },
      }
    );
  }
});
