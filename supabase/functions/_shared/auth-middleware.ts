/**
 * Shared Authentication Middleware for Supabase Edge Functions
 *
 * This module provides secure authentication and tenant validation utilities
 * to prevent cross-tenant data access vulnerabilities in Edge Functions.
 *
 * SECURITY CRITICAL: Always validate that the authenticated user belongs to
 * the tenant_id they're attempting to access. Never trust tenant_id from
 * request parameters without validation.
 *
 * @module auth-middleware
 */

import { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { getCorsHeaders, handleCorsPreflight } from './cors.ts';

// Re-export CORS utilities for convenience
export { getCorsHeaders, handleCorsPreflight };

// ============================================================================
// Types and Interfaces
// ============================================================================

/**
 * Result of successful authentication
 */
export interface AuthResult {
  userId: string;
  tenantId: string;
  role: string;
}

/**
 * Result of failed authentication
 */
export interface AuthError {
  error: string;
  statusCode: number;
  details?: string;
}

/**
 * Profile data structure from the database
 */
interface ProfileData {
  user_id: string;
  tenant_id: string;
  role: string;
}

/**
 * @deprecated Use getCorsHeaders(req) from cors.ts instead.
 * This is a non-permissive fallback for code that doesn't have access to the request object.
 * It does NOT set Access-Control-Allow-Origin, so browsers will block cross-origin requests.
 */
export const corsHeaders: Record<string, string> = {
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-api-key',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE',
};

// ============================================================================
// Authentication Token Extraction
// ============================================================================

/**
 * Extracts the authentication token from the request headers.
 *
 * Supports two authentication methods:
 * 1. Standard Authorization header (Bearer token)
 * 2. Custom X-AISAC-Token header (encrypted token)
 *
 * @param req - The incoming HTTP request
 * @returns The extracted token or null if not found
 *
 * @example
 * ```typescript
 * const token = extractAuthToken(req);
 * if (!token) {
 *   return new Response(JSON.stringify({ error: 'Missing authentication token' }), {
 *     status: 401,
 *     headers: { ...corsHeaders, 'Content-Type': 'application/json' }
 *   });
 * }
 * ```
 */
export function extractAuthToken(req: Request): string | null {
  // Try Authorization header first (standard Supabase auth)
  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Try X-AISAC-Token header (custom encrypted token)
  const aisacToken = req.headers.get('x-aisac-token');
  if (aisacToken) {
    return aisacToken;
  }

  return null;
}

// ============================================================================
// Token Verification and User Extraction
// ============================================================================

/**
 * Verifies a Supabase JWT token and extracts user information.
 *
 * This function validates the token with Supabase Auth and returns the
 * authenticated user's ID. For encrypted tokens, use decryptToken from
 * crypto-utils.ts first.
 *
 * @param supabase - Supabase client instance
 * @param token - JWT token to verify
 * @returns User ID if verification succeeds, null otherwise
 *
 * @example
 * ```typescript
 * const userId = await verifyTokenAndGetUser(supabase, token);
 * if (!userId) {
 *   return new Response(JSON.stringify({ error: 'Invalid token' }), {
 *     status: 401,
 *     headers: { ...corsHeaders, 'Content-Type': 'application/json' }
 *   });
 * }
 * ```
 */
export async function verifyTokenAndGetUser(
  supabase: SupabaseClient,
  token: string
): Promise<string | null> {
  try {
    const {
      data: { user },
      error,
    } = await supabase.auth.getUser(token);

    if (error) {
      console.error('Token verification failed:', error.message);
      return null;
    }

    if (!user) {
      console.error('Token verification failed: No user found');
      return null;
    }

    return user.id;
  } catch (error) {
    console.error('Error verifying token:', error);
    return null;
  }
}

// ============================================================================
// Tenant Access Validation - CRITICAL SECURITY FUNCTION
// ============================================================================

/**
 * Validates that a user has access to a specific tenant.
 *
 * CRITICAL SECURITY: This function prevents cross-tenant data access by
 * verifying that the authenticated user actually belongs to the tenant
 * they're trying to access.
 *
 * Implementation:
 * 1. Queries the profiles table for the user's tenant assignment
 * 2. Compares the user's actual tenant_id with the requested tenant_id
 * 3. Returns the user's profile data only if validation succeeds
 *
 * Security Logging:
 * - Does NOT log tenant_id or user_id in production to prevent log leakage
 * - Logs only boolean validation results and error types
 *
 * @param supabase - Supabase client instance (must use service role key)
 * @param userId - Authenticated user's ID from verified token
 * @param requestedTenantId - Tenant ID from the request (untrusted until validated)
 * @returns AuthResult if validation succeeds, AuthError if it fails
 *
 * @example
 * ```typescript
 * const validation = await validateTenantAccess(supabase, userId, requestedTenantId);
 * if ('error' in validation) {
 *   return new Response(JSON.stringify({ error: validation.error }), {
 *     status: validation.statusCode,
 *     headers: { ...corsHeaders, 'Content-Type': 'application/json' }
 *   });
 * }
 *
 * // validation is AuthResult type here
 * const { userId, tenantId, role } = validation;
 * // Proceed with tenant-scoped operations using validated tenantId
 * ```
 */
export async function validateTenantAccess(
  supabase: SupabaseClient,
  userId: string,
  requestedTenantId: string
): Promise<AuthResult | AuthError> {
  try {
    // Query user's profile to get their actual tenant_id
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('user_id, tenant_id, role')
      .eq('user_id', userId)
      .maybeSingle();

    if (profileError) {
      console.error('Profile query failed:', profileError.message);
      return {
        error: 'Failed to verify user profile',
        statusCode: 500,
        details: profileError.message,
      };
    }

    if (!profile) {
      console.error('User profile not found - user may not be properly provisioned');
      return {
        error: 'User profile not found',
        statusCode: 403,
        details: 'User account is not properly configured',
      };
    }

    // CRITICAL: Validate that the user's actual tenant_id matches the requested one
    if (profile.tenant_id !== requestedTenantId) {
      console.error('Tenant access violation detected - blocked');
      // Security log: Don't include actual IDs to prevent log leakage
      return {
        error: 'Access denied: Invalid tenant',
        statusCode: 403,
        details: 'You do not have access to the requested tenant',
      };
    }

    // Validation successful - return authenticated user info
    console.log('Tenant access validated successfully');
    return {
      userId: profile.user_id,
      tenantId: profile.tenant_id,
      role: profile.role,
    };
  } catch (error) {
    console.error('Unexpected error during tenant validation:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return {
      error: 'Internal authentication error',
      statusCode: 500,
      details: errorMessage,
    };
  }
}

// ============================================================================
// Combined Authentication Flow
// ============================================================================

/**
 * Complete authentication and authorization flow for Edge Functions.
 *
 * This is the primary function to use in most Edge Functions. It combines
 * token extraction, verification, and tenant validation into a single call.
 *
 * Workflow:
 * 1. Extracts token from request headers
 * 2. Verifies token with Supabase Auth
 * 3. Validates user has access to the requested tenant
 * 4. Returns complete auth result or error response
 *
 * @param req - The incoming HTTP request
 * @param supabase - Supabase client instance (must use service role key)
 * @param requestedTenantId - Tenant ID from request body/params (will be validated)
 * @returns AuthResult if authentication succeeds, AuthError if it fails
 *
 * @example
 * ```typescript
 * const authResult = await authenticateRequest(req, supabase, body.tenant_id);
 * if ('error' in authResult) {
 *   return new Response(JSON.stringify({ error: authResult.error }), {
 *     status: authResult.statusCode,
 *     headers: { ...corsHeaders, 'Content-Type': 'application/json' }
 *   });
 * }
 *
 * // Proceed with authenticated and authorized request
 * const { userId, tenantId, role } = authResult;
 * // Use validated tenantId for all database operations
 * ```
 */
export async function authenticateRequest(
  req: Request,
  supabase: SupabaseClient,
  requestedTenantId: string
): Promise<AuthResult | AuthError> {
  // Extract authentication token
  const token = extractAuthToken(req);
  if (!token) {
    return {
      error: 'Missing authentication token',
      statusCode: 401,
      details: 'No Authorization header or X-AISAC-Token found',
    };
  }

  // Verify token and get user ID
  const userId = await verifyTokenAndGetUser(supabase, token);
  if (!userId) {
    return {
      error: 'Invalid or expired token',
      statusCode: 401,
      details: 'Token verification failed',
    };
  }

  // Validate tenant access
  return await validateTenantAccess(supabase, userId, requestedTenantId);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Creates a standardized error response for authentication failures.
 *
 * @param authError - The authentication error object
 * @returns HTTP Response object with error details
 *
 * @example
 * ```typescript
 * const authResult = await authenticateRequest(req, supabase, body.tenant_id);
 * if ('error' in authResult) {
 *   return createAuthErrorResponse(authResult);
 * }
 * ```
 */
export function createAuthErrorResponse(authError: AuthError): Response {
  return new Response(
    JSON.stringify({
      error: authError.error,
      details: authError.details,
    }),
    {
      status: authError.statusCode,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    }
  );
}

/**
 * Checks if a value is an AuthError type (type guard).
 *
 * @param result - Value to check
 * @returns True if the value is an AuthError
 *
 * @example
 * ```typescript
 * const result = await validateTenantAccess(supabase, userId, tenantId);
 * if (isAuthError(result)) {
 *   return createAuthErrorResponse(result);
 * }
 * // TypeScript now knows result is AuthResult
 * ```
 */
export function isAuthError(result: AuthResult | AuthError): result is AuthError {
  return 'error' in result;
}

// ============================================================================
// Usage Examples and Best Practices
// ============================================================================

/**
 * EXAMPLE 1: Basic Edge Function with Authentication
 *
 * ```typescript
 * import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
 * import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
 * import { authenticateRequest, createAuthErrorResponse, corsHeaders } from '../_shared/auth-middleware.ts';
 *
 * serve(async (req) => {
 *   if (req.method === 'OPTIONS') {
 *     return new Response(null, { headers: corsHeaders });
 *   }
 *
 *   try {
 *     const supabase = createClient(
 *       Deno.env.get('SUPABASE_URL')!,
 *       Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
 *     );
 *
 *     const body = await req.json();
 *
 *     // Authenticate and validate tenant access
 *     const authResult = await authenticateRequest(req, supabase, body.tenant_id);
 *     if ('error' in authResult) {
 *       return createAuthErrorResponse(authResult);
 *     }
 *
 *     // Use validated tenantId for database operations
 *     const { tenantId, userId, role } = authResult;
 *
 *     const { data, error } = await supabase
 *       .from('your_table')
 *       .insert({
 *         tenant_id: tenantId,  // Use validated tenantId, NOT body.tenant_id
 *         user_id: userId,
 *         // ... other fields
 *       });
 *
 *     // ... rest of your logic
 *   } catch (error) {
 *     return new Response(JSON.stringify({ error: 'Internal server error' }), {
 *       status: 500,
 *       headers: { ...corsHeaders, 'Content-Type': 'application/json' }
 *     });
 *   }
 * });
 * ```
 *
 * EXAMPLE 2: Using Individual Functions for Custom Flows
 *
 * ```typescript
 * import { validateTenantAccess, extractAuthToken, verifyTokenAndGetUser } from '../_shared/auth-middleware.ts';
 * import { decryptToken } from '../_shared/crypto-utils.ts';
 *
 * serve(async (req) => {
 *   // Custom token handling (encrypted token)
 *   const encryptedToken = req.headers.get('x-aisac-token');
 *   const encKey = Deno.env.get('WEBHOOK_ENC_KEY')!;
 *   const payload = await decryptToken(encryptedToken, encKey);
 *
 *   if (!payload) {
 *     return new Response(JSON.stringify({ error: 'Invalid token' }), {
 *       status: 401,
 *       headers: { ...corsHeaders, 'Content-Type': 'application/json' }
 *     });
 *   }
 *
 *   // Validate tenant access using decrypted user_id and tenant_id
 *   const validation = await validateTenantAccess(supabase, payload.user_id, payload.tenant_id);
 *   if ('error' in validation) {
 *     return createAuthErrorResponse(validation);
 *   }
 *
 *   // Proceed with validated credentials
 * });
 * ```
 *
 * SECURITY BEST PRACTICES:
 *
 * 1. ✅ ALWAYS validate tenant access before database operations
 * 2. ✅ NEVER trust tenant_id from request parameters without validation
 * 3. ✅ Use the validated tenantId from AuthResult, not from request body
 * 4. ✅ Use service role key for supabase client in Edge Functions
 * 5. ✅ Log authentication failures but don't include sensitive IDs
 * 6. ✅ Return generic error messages to clients, detailed logs server-side
 * 7. ❌ DON'T skip tenant validation for "system" or "admin" operations
 * 8. ❌ DON'T log tenant_id or user_id in production environments
 * 9. ❌ DON'T assume the user is authorized based on token alone
 * 10. ❌ DON'T use anon key - always use service role for Edge Functions
 */
