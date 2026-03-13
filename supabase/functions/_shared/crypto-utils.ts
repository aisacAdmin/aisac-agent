/**
 * Shared Cryptographic Utilities for Supabase Edge Functions
 *
 * This module provides:
 * - AES-GCM encryption/decryption for secure token handling
 * - DRA (Double Ratchet Algorithm) primitives for MCP auth token rotation:
 *   - X25519 Diffie-Hellman key exchange (via @noble/curves)
 *   - HKDF-SHA256 key derivation
 *   - Symmetric chain advance (forward secrecy)
 *   - DH ratchet step (break-in recovery)
 *
 * @module crypto-utils
 */

import { x25519 } from 'https://esm.sh/@noble/curves@1.8.1/ed25519';

// ============================================================================
// Types and Interfaces
// ============================================================================

export interface DecryptedTokenPayload {
  tenant_id: string;
  user_id: string;
  exp: number;
  nonce: string;
  v?: number;
  asset_id?: string;
  execution_id?: string;
}

export type TokenFormat = 'dot-separated' | 'colon-separated' | 'json-base64';

export interface X25519Keypair {
  publicKey: string;  // base64url-encoded 32 bytes
  privateKey: string; // base64url-encoded 32 bytes
}

export interface ChainAdvanceResult {
  newChainKey: string; // base64url-encoded
  mcpToken: string;    // wazuh_<base64url> format (49 chars)
}

export interface RatchetStepResult {
  newRootKey: string;  // base64url-encoded
  newChainKey: string; // base64url-encoded
}

export interface DRAInitResult {
  rootKey: string;   // base64url-encoded
  chainKey: string;  // base64url-encoded
  mcpToken: string;  // wazuh_<base64url> format
}

// ============================================================================
// Base64 Encoding/Decoding Utilities
// ============================================================================

export function b64ToBytes(b64: string): Uint8Array {
  const normalized = b64
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/\s/g, '');

  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const bin = atob(normalized + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

export function bytesToB64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
  const b64 = btoa(binString);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ============================================================================
// Token Decryption
// ============================================================================

export async function decryptToken(
  encToken: string,
  keyB64: string
): Promise<DecryptedTokenPayload | null> {
  try {
    let ivBytes: Uint8Array | null = null;
    let ctBytes: Uint8Array | null = null;

    const dotParts = encToken.split('.');
    if (dotParts.length === 2) {
      ivBytes = b64ToBytes(dotParts[0]);
      ctBytes = b64ToBytes(dotParts[1]);
    } else if (encToken.includes(':')) {
      const colonParts = encToken.split(':');
      if (colonParts.length === 2) {
        ivBytes = b64ToBytes(colonParts[0]);
        ctBytes = b64ToBytes(colonParts[1]);
      }
    } else {
      try {
        const jsonBytes = b64ToBytes(encToken);
        const jsonStr = new TextDecoder().decode(jsonBytes);
        const obj = JSON.parse(jsonStr) as { iv: string; ct: string };
        if (!obj.iv || !obj.ct) throw new Error('Invalid JSON token structure');
        ivBytes = b64ToBytes(obj.iv);
        ctBytes = b64ToBytes(obj.ct);
      } catch (jsonError) {
        console.error('Failed to parse JSON token format:', jsonError);
        return null;
      }
    }

    if (!ivBytes || !ctBytes) {
      console.error('Invalid token format: unable to extract IV and ciphertext');
      return null;
    }

    const keyBytes = b64ToBytes(keyB64);
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
      'decrypt',
    ]);

    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      cryptoKey,
      ctBytes
    );

    const json = new TextDecoder().decode(plainBuf);
    const payload = JSON.parse(json) as Partial<DecryptedTokenPayload>;

    if (!payload.tenant_id || !payload.user_id || !payload.exp || !payload.nonce) {
      console.error('Invalid token payload: missing required fields');
      return null;
    }

    return {
      tenant_id: payload.tenant_id,
      user_id: payload.user_id,
      exp: Number(payload.exp),
      nonce: String(payload.nonce),
      v: payload.v,
      asset_id: payload.asset_id,
      execution_id: payload.execution_id,
    };
  } catch (error) {
    console.error('Token decryption failed:', error);
    return null;
  }
}

// ============================================================================
// Token Encryption
// ============================================================================

export async function encryptToken(
  payload: DecryptedTokenPayload,
  keyB64: string,
  format: TokenFormat = 'dot-separated'
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyBytes = b64ToBytes(keyB64);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);

  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext);
  const ctBytes = new Uint8Array(ciphertext);

  const ivB64 = bytesToB64(iv);
  const ctB64 = bytesToB64(ctBytes);

  switch (format) {
    case 'dot-separated':
      return `${ivB64}.${ctB64}`;
    case 'colon-separated':
      return `${ivB64}:${ctB64}`;
    case 'json-base64': {
      const obj = { iv: ivB64, ct: ctB64 };
      const jsonStr = JSON.stringify(obj);
      const jsonBytes = new TextEncoder().encode(jsonStr);
      return bytesToB64(jsonBytes);
    }
    default:
      return `${ivB64}.${ctB64}`;
  }
}

// ============================================================================
// Token Validation Utilities
// ============================================================================

export function isTokenValid(exp: number, maxFutureDrift: number = 7200): boolean {
  const nowSec = Math.floor(Date.now() / 1000);
  if (exp <= nowSec) return false;
  if (exp - nowSec > maxFutureDrift) return false;
  return true;
}

export function generateNonce(): string {
  return crypto.randomUUID();
}

export function createTokenPayload(
  tenantId: string,
  userId: string,
  expiresInSeconds: number = 1800
): DecryptedTokenPayload {
  return {
    tenant_id: tenantId,
    user_id: userId,
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
    nonce: generateNonce(),
    v: 1,
  };
}

// ============================================================================
// String Encryption/Decryption (for storing secrets like API tokens)
// ============================================================================

export async function encryptString(plaintext: string, keyB64: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyBytes = b64ToBytes(keyB64);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);

  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoded);

  return `${bytesToB64(iv)}.${bytesToB64(new Uint8Array(ciphertext))}`;
}

export async function decryptString(encrypted: string, keyB64: string): Promise<string | null> {
  try {
    const parts = encrypted.split('.');
    if (parts.length !== 2) {
      console.error('Invalid encrypted string format: expected iv.ciphertext');
      return null;
    }

    const ivBytes = b64ToBytes(parts[0]);
    const ctBytes = b64ToBytes(parts[1]);
    const keyBytes = b64ToBytes(keyB64);
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
      'decrypt',
    ]);

    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      cryptoKey,
      ctBytes
    );
    return new TextDecoder().decode(plainBuf);
  } catch (error) {
    console.error('String decryption failed:', error);
    return null;
  }
}

// ============================================================================
// DRA (Double Ratchet Algorithm) Primitives
// ============================================================================

/**
 * Generate an X25519 keypair for Diffie-Hellman key exchange.
 * Uses @noble/curves for audited pure-JS X25519.
 */
export function generateX25519Keypair(): X25519Keypair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    publicKey: bytesToB64(publicKey),
    privateKey: bytesToB64(privateKey),
  };
}

/**
 * Compute X25519 shared secret from our private key and peer's public key.
 * Returns raw 32-byte shared secret.
 */
export function computeSharedSecret(privateKeyB64: string, peerPublicKeyB64: string): Uint8Array {
  const privateKey = b64ToBytes(privateKeyB64);
  const publicKey = b64ToBytes(peerPublicKeyB64);
  return x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * HKDF-SHA256 key derivation.
 *
 * @param ikm   - Input keying material
 * @param salt  - Salt string (converted to UTF-8 bytes)
 * @param info  - Context/info string (converted to UTF-8 bytes)
 * @param length - Output length in bytes (default 32)
 */
export async function hkdfDerive(
  ikm: Uint8Array,
  salt: string,
  info: string,
  length: number = 32
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ikm,
    'HKDF',
    false,
    ['deriveBits']
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(salt),
      info: new TextEncoder().encode(info),
    },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derived);
}

/**
 * Format 32 bytes as a Wazuh MCP API key: wazuh_<base64url> (49 chars total).
 */
export function formatAsWazuhKey(tokenBytes: Uint8Array): string {
  return `wazuh_${bytesToB64(tokenBytes)}`;
}

/**
 * Initialize DRA state from X25519 shared secret (during registration).
 *
 * root_key_0  = HKDF(shared_secret, salt="aisac-mcp-root", info="aisac-mcp-root-init")
 * chain_key_0 = HKDF(root_key_0,    salt="aisac-mcp-chain-salt", info="aisac-mcp-chain")
 * mcp_token_0 = HKDF(chain_key_0,   salt="aisac-mcp-salt", info="aisac-mcp-token")
 */
export async function initializeDRA(dhSharedSecret: Uint8Array): Promise<DRAInitResult> {
  const rootKey = await hkdfDerive(dhSharedSecret, 'aisac-mcp-root', 'aisac-mcp-root-init', 32);
  const chainKey = await hkdfDerive(rootKey, 'aisac-mcp-chain-salt', 'aisac-mcp-chain', 32);
  const tokenBytes = await hkdfDerive(chainKey, 'aisac-mcp-salt', 'aisac-mcp-token', 32);

  return {
    rootKey: bytesToB64(rootKey),
    chainKey: bytesToB64(chainKey),
    mcpToken: formatAsWazuhKey(tokenBytes),
  };
}

/**
 * Derive current MCP token from chain key (without advancing the chain).
 * Used by mcp-token edge function to get the current valid token.
 */
export async function deriveTokenFromChain(chainKeyB64: string): Promise<string> {
  const chainKey = b64ToBytes(chainKeyB64);
  const tokenBytes = await hkdfDerive(chainKey, 'aisac-mcp-salt', 'aisac-mcp-token', 32);
  return formatAsWazuhKey(tokenBytes);
}

/**
 * Advance the symmetric chain (24h rotation via cronjob).
 * Produces the new token AND advances the chain key (one-way = forward secrecy).
 *
 * token     = HKDF(chain_key, salt="aisac-mcp-salt", info="aisac-mcp-token")
 * new_chain = HKDF(chain_key, salt="aisac-mcp-salt", info="aisac-mcp-advance")
 */
export async function advanceChain(chainKeyB64: string): Promise<ChainAdvanceResult> {
  const chainKey = b64ToBytes(chainKeyB64);

  const tokenBytes = await hkdfDerive(chainKey, 'aisac-mcp-salt', 'aisac-mcp-token', 32);
  const newChainKey = await hkdfDerive(chainKey, 'aisac-mcp-salt', 'aisac-mcp-advance', 32);

  return {
    newChainKey: bytesToB64(newChainKey),
    mcpToken: formatAsWazuhKey(tokenBytes),
  };
}

/**
 * DH ratchet step: combine old root key with new DH shared secret
 * to derive new root key and chain key (break-in recovery).
 *
 * combined  = old_root || dh_shared_secret
 * new_root  = HKDF(combined, salt="aisac-mcp-root", info="aisac-mcp-root-derive")
 * new_chain = HKDF(new_root, salt="aisac-mcp-chain-salt", info="aisac-mcp-chain")
 */
export async function ratchetStep(
  rootKeyB64: string,
  dhSharedSecret: Uint8Array
): Promise<RatchetStepResult> {
  const rootKey = b64ToBytes(rootKeyB64);

  // Concatenate root key and DH shared secret as IKM
  const combined = new Uint8Array(rootKey.length + dhSharedSecret.length);
  combined.set(rootKey, 0);
  combined.set(dhSharedSecret, rootKey.length);

  const newRootKey = await hkdfDerive(combined, 'aisac-mcp-root', 'aisac-mcp-root-derive', 32);
  const newChainKey = await hkdfDerive(newRootKey, 'aisac-mcp-chain-salt', 'aisac-mcp-chain', 32);

  return {
    newRootKey: bytesToB64(newRootKey),
    newChainKey: bytesToB64(newChainKey),
  };
}
