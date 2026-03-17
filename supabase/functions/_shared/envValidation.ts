/**
 * Environment Variable Validation Utility
 *
 * Validates required environment variables are present before Edge Function execution.
 * Critical security fix to prevent functions from running with missing configuration.
 *
 * @module envValidation
 */

export interface EnvValidationResult {
  valid: boolean;
  missing: string[];
  error?: string;
}

/**
 * Validates that all required environment variables are present
 *
 * @param required - Array of required environment variable names
 * @returns Validation result with missing variables if any
 */
export function validateEnvironment(required: string[]): EnvValidationResult {
  const missing: string[] = [];

  for (const envVar of required) {
    const value = Deno.env.get(envVar);
    if (!value || value.trim() === '') {
      missing.push(envVar);
    }
  }

  if (missing.length > 0) {
    return {
      valid: false,
      missing,
      error: `Missing required environment variables: ${missing.join(', ')}`,
    };
  }

  return {
    valid: true,
    missing: [],
  };
}

/**
 * Creates a standardized error response for missing environment variables
 *
 * @param result - Validation result from validateEnvironment
 * @returns Response object with 500 status
 */
export function createEnvErrorResponse(result: EnvValidationResult): Response {
  console.error('Environment validation failed:', result.error);
  console.error('Missing variables:', result.missing);

  return new Response(
    JSON.stringify({
      error: 'Server configuration error',
      message: 'The server is not properly configured. Please contact support.',
      // Don't expose which variables are missing to prevent information disclosure
    }),
    {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'X-Error-Type': 'CONFIGURATION_ERROR',
      },
    }
  );
}

/**
 * Common required environment variables for Supabase Edge Functions
 */
export const COMMON_SUPABASE_ENV = [
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
];

/**
 * Validates common Supabase environment variables
 * Returns Response if validation fails, null if valid
 */
export function validateSupabaseEnv(): Response | null {
  const result = validateEnvironment(COMMON_SUPABASE_ENV);

  if (!result.valid) {
    return createEnvErrorResponse(result);
  }

  return null;
}
