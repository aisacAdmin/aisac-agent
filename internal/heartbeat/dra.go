// Package heartbeat - DRA (Double Ratchet Algorithm) primitives for MCP auth token rotation.
//
// Implements X25519 DH key exchange + HKDF-SHA256 key derivation matching
// the TypeScript implementation in supabase/functions/_shared/crypto-utils.ts.
//
// Security properties:
//   - Forward secrecy: HKDF chain is one-way (compromising token_n doesn't reveal token_{n-1})
//   - Break-in recovery: DH ratchet on heartbeat resets the chain with fresh randomness
//   - Self-healing: next heartbeat DH step generates independent material
package heartbeat

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DRAContext holds domain separation parameters for HKDF derivations.
// Binds all derived keys to a specific asset and tenant.
type DRAContext struct {
	AssetID  string `json:"asset_id"`  // UUID — mixed into salt (per-installation entropy)
	TenantID string `json:"tenant_id"` // UUID — mixed into info (per-tenant domain separation)
}

// DRAState holds the current Double Ratchet Algorithm state.
type DRAState struct {
	RootKey     string `json:"root_key"`      // base64url-encoded 32 bytes
	ChainKey    string `json:"chain_key"`     // base64url-encoded 32 bytes
	DHPublicKey string `json:"dh_public_key"` // our current public key (base64url)
	DHPrivKey   string `json:"dh_priv_key"`   // our current private key (base64url)
	PeerDHPub   string `json:"peer_dh_pub"`   // platform's current DH public key (base64url)
	AssetID     string `json:"asset_id"`      // for domain separation
	TenantID    string `json:"tenant_id"`     // for domain separation
}

// DRAInitResult contains the result of DRA initialization.
type DRAInitResult struct {
	RootKey  string // base64url-encoded
	ChainKey string // base64url-encoded
	McpToken string // wazuh_<base64url> format
}

// b64urlEncode encodes bytes to unpadded base64url.
func b64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// b64urlDecode decodes unpadded base64url to bytes.
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// GenerateX25519Keypair generates a new X25519 keypair.
func GenerateX25519Keypair() (pubB64, privB64 string, err error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate X25519 key: %w", err)
	}
	return b64urlEncode(privKey.PublicKey().Bytes()), b64urlEncode(privKey.Bytes()), nil
}

// ComputeSharedSecret computes X25519(ourPriv, peerPub).
func ComputeSharedSecret(ourPrivB64, peerPubB64 string) ([]byte, error) {
	privBytes, err := b64urlDecode(ourPrivB64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	pubBytes, err := b64urlDecode(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("import private key: %w", err)
	}
	pubKey, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("import public key: %w", err)
	}

	shared, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	return shared, nil
}

// hkdfDerive derives key material using HKDF-SHA256.
// Must match the TypeScript hkdfDerive(ikm, salt, info, length) exactly.
func hkdfDerive(ikm []byte, salt, info string, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, []byte(salt), info, length)
}

// FormatAsWazuhKey formats 32 bytes as wazuh_<base64url> (49 chars total).
func FormatAsWazuhKey(tokenBytes []byte) string {
	return "wazuh_" + b64urlEncode(tokenBytes)
}

// InitializeDRA creates the initial DRA state from a shared secret.
// Must match TypeScript initializeDRA() exactly.
//
//	root_key_0  = HKDF(shared_secret, salt="aisac-mcp-root:{asset_id}", info="aisac-mcp-root-init:{tenant_id}")
//	chain_key_0 = HKDF(root_key_0,    salt="aisac-mcp-chain-salt:{asset_id}", info="aisac-mcp-chain:{tenant_id}")
//	mcp_token_0 = HKDF(chain_key_0,   salt="aisac-mcp-salt:{asset_id}", info="aisac-mcp-token:{tenant_id}")
func InitializeDRA(dhSharedSecret []byte, ctx DRAContext) (*DRAInitResult, error) {
	rootKey, err := hkdfDerive(dhSharedSecret, "aisac-mcp-root:"+ctx.AssetID, "aisac-mcp-root-init:"+ctx.TenantID, 32)
	if err != nil {
		return nil, err
	}
	chainKey, err := hkdfDerive(rootKey, "aisac-mcp-chain-salt:"+ctx.AssetID, "aisac-mcp-chain:"+ctx.TenantID, 32)
	if err != nil {
		return nil, err
	}
	tokenBytes, err := hkdfDerive(chainKey, "aisac-mcp-salt:"+ctx.AssetID, "aisac-mcp-token:"+ctx.TenantID, 32)
	if err != nil {
		return nil, err
	}
	return &DRAInitResult{
		RootKey:  b64urlEncode(rootKey),
		ChainKey: b64urlEncode(chainKey),
		McpToken: FormatAsWazuhKey(tokenBytes),
	}, nil
}

// DeriveTokenFromChain derives the current MCP token from a chain key without advancing.
// Must match TypeScript deriveTokenFromChain().
func DeriveTokenFromChain(chainKeyB64 string, ctx DRAContext) (string, error) {
	chainKey, err := b64urlDecode(chainKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode chain key: %w", err)
	}
	tokenBytes, err := hkdfDerive(chainKey, "aisac-mcp-salt:"+ctx.AssetID, "aisac-mcp-token:"+ctx.TenantID, 32)
	if err != nil {
		return "", err
	}
	return FormatAsWazuhKey(tokenBytes), nil
}

// AdvanceChain advances the symmetric chain and returns the new token + chain key.
// Must match TypeScript advanceChain().
//
//	token     = HKDF(chain_key, salt="aisac-mcp-salt:{asset_id}", info="aisac-mcp-token:{tenant_id}")
//	new_chain = HKDF(chain_key, salt="aisac-mcp-salt:{asset_id}", info="aisac-mcp-advance:{tenant_id}")
func AdvanceChain(chainKeyB64 string, ctx DRAContext) (newChainKeyB64, mcpToken string, err error) {
	chainKey, err := b64urlDecode(chainKeyB64)
	if err != nil {
		return "", "", fmt.Errorf("decode chain key: %w", err)
	}
	tokenBytes, err := hkdfDerive(chainKey, "aisac-mcp-salt:"+ctx.AssetID, "aisac-mcp-token:"+ctx.TenantID, 32)
	if err != nil {
		return "", "", err
	}
	newChainKey, err := hkdfDerive(chainKey, "aisac-mcp-salt:"+ctx.AssetID, "aisac-mcp-advance:"+ctx.TenantID, 32)
	if err != nil {
		return "", "", err
	}
	return b64urlEncode(newChainKey), FormatAsWazuhKey(tokenBytes), nil
}

// RatchetStep performs a DH ratchet step: combines root key with new DH shared secret.
// Must match TypeScript ratchetStep().
//
//	combined  = old_root || dh_shared_secret
//	new_root  = HKDF(combined, salt="aisac-mcp-root:{asset_id}", info="aisac-mcp-root-derive:{tenant_id}")
//	new_chain = HKDF(new_root, salt="aisac-mcp-chain-salt:{asset_id}", info="aisac-mcp-chain:{tenant_id}")
func RatchetStep(rootKeyB64 string, dhSharedSecret []byte, ctx DRAContext) (newRootKeyB64, newChainKeyB64 string, err error) {
	rootKey, err := b64urlDecode(rootKeyB64)
	if err != nil {
		return "", "", fmt.Errorf("decode root key: %w", err)
	}

	// Concatenate root key and DH shared secret
	combined := make([]byte, len(rootKey)+len(dhSharedSecret))
	copy(combined, rootKey)
	copy(combined[len(rootKey):], dhSharedSecret)

	newRootKey, err := hkdfDerive(combined, "aisac-mcp-root:"+ctx.AssetID, "aisac-mcp-root-derive:"+ctx.TenantID, 32)
	if err != nil {
		return "", "", err
	}
	newChainKey, err := hkdfDerive(newRootKey, "aisac-mcp-chain-salt:"+ctx.AssetID, "aisac-mcp-chain:"+ctx.TenantID, 32)
	if err != nil {
		return "", "", err
	}
	return b64urlEncode(newRootKey), b64urlEncode(newChainKey), nil
}

// DRA state file path
const draStateDir = "/etc/aisac"
const draStateFile = "mcp-dra-state.json"

// SaveDRAState persists the DRA state to disk.
func SaveDRAState(state *DRAState) error {
	if err := os.MkdirAll(draStateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal DRA state: %w", err)
	}
	path := filepath.Join(draStateDir, draStateFile)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write DRA state: %w", err)
	}
	return nil
}

// LoadDRAState loads the DRA state from disk.
func LoadDRAState() (*DRAState, error) {
	path := filepath.Join(draStateDir, draStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read DRA state: %w", err)
	}
	var state DRAState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal DRA state: %w", err)
	}
	return &state, nil
}
