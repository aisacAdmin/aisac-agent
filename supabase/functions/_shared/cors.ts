/**
 * CORS Configuration for Edge Functions
 *
 * SECURITY: Restricts CORS to trusted domains only
 * - Production: app.aisac.es, aisac.cisec.es
 * - Staging: aisac-staging.netlify.app
 * - Development: localhost:8080, localhost:5173
 *
 * Prevents CSRF attacks by rejecting wildcard origins
 */

// ============================================================================
// Allowed Origins Whitelist
// ============================================================================

const ALLOWED_ORIGINS = [
  // Production domain (principal)
  'https://aisac.cisec.es',

  // Staging domain
  'https://aisac-staging.netlify.app',

  // Development (localhost)
  'http://localhost:8080',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://127.0.0.1:8080',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:3000',

  // Supabase Studio (for testing)
  'https://app.supabase.com',
  'https://supabase.com',
];

// ============================================================================
// CORS Headers Helper
// ============================================================================

/**
 * Get CORS headers for the given request
 * Validates origin against whitelist and returns appropriate headers
 *
 * @param request - The incoming request
 * @returns CORS headers object
 */
export function getCorsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get('origin');

  // If no origin header, don't set CORS (likely server-to-server)
  if (!origin) {
    return {
      'Access-Control-Allow-Headers':
        'authorization, x-client-info, apikey, content-type, x-requested-with, x-api-key',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE',
      'Access-Control-Max-Age': '86400', // 24 hours
    };
  }

  // Check if origin is in whitelist or any localhost/127.0.0.1 port
  const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  const isAllowed = isLocalhost || ALLOWED_ORIGINS.includes(origin);

  if (isAllowed) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers':
        'authorization, x-client-info, apikey, content-type, x-requested-with, stripe-signature, x-api-key',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400', // 24 hours
    };
  }

  // Origin not allowed - return restrictive headers
  console.warn(`[CORS] Rejected origin: ${origin}`);
  return {
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-api-key',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    // No Access-Control-Allow-Origin header = browser will block
  };
}

/**
 * Handle CORS preflight (OPTIONS) requests
 *
 * @param request - The OPTIONS request
 * @returns Response with CORS headers
 */
export function handleCorsPreflight(request: Request): Response {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(request),
  });
}

/**
 * Create JSON response with CORS headers
 *
 * @param data - Response data
 * @param status - HTTP status code
 * @param request - Original request (for CORS validation)
 * @returns Response with CORS headers
 */
export function corsJsonResponse(data: unknown, status: number, request: Request): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...getCorsHeaders(request),
      'Content-Type': 'application/json',
    },
  });
}

/**
 * Legacy wildcard CORS headers (DEPRECATED - DO NOT USE)
 * Kept for reference only
 */
export const LEGACY_WILDCARD_CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};
