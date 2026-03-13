package heartbeat

import (
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

// TestCrossPlatformDRA verifies that Go's DRA implementation produces identical
// outputs to TypeScript/Deno and Python/bash for the same inputs.
//
// Run this test, then feed the printed test vectors to the Deno verification
// script (scripts/verify-dra-crossplatform.ts) and the Python verification
// script. ALL must produce identical values.
//
// If any implementation diverges, agent ↔ platform auth will silently break.
func TestCrossPlatformDRA(t *testing.T) {
	// Fixed test keypairs (deterministic hex → X25519 private keys)
	alicePrivHex := "a8abababababababababababababababababababababababababababababababab"[:64]
	bobPrivHex := "b8babababababababababababababababababababababababababababababababc"[:64]

	alicePrivBytes, _ := hex.DecodeString(alicePrivHex)
	bobPrivBytes, _ := hex.DecodeString(bobPrivHex)

	curve := ecdh.X25519()

	alicePriv, err := curve.NewPrivateKey(alicePrivBytes)
	if err != nil {
		t.Fatalf("import alice priv: %v", err)
	}
	bobPriv, err := curve.NewPrivateKey(bobPrivBytes)
	if err != nil {
		t.Fatalf("import bob priv: %v", err)
	}

	alicePrivB64 := b64urlEncode(alicePrivBytes)
	alicePubB64 := b64urlEncode(alicePriv.PublicKey().Bytes())
	bobPrivB64 := b64urlEncode(bobPrivBytes)
	bobPubB64 := b64urlEncode(bobPriv.PublicKey().Bytes())

	// 1. Shared secret (Alice priv × Bob pub == Bob priv × Alice pub)
	ss1, err := ComputeSharedSecret(alicePrivB64, bobPubB64)
	if err != nil {
		t.Fatalf("shared secret A×B: %v", err)
	}
	ss2, err := ComputeSharedSecret(bobPrivB64, alicePubB64)
	if err != nil {
		t.Fatalf("shared secret B×A: %v", err)
	}
	ssB64 := b64urlEncode(ss1)
	if b64urlEncode(ss2) != ssB64 {
		t.Fatal("DH shared secrets don't match between directions")
	}

	// 2. DRA initialization
	init, err := InitializeDRA(ss1)
	if err != nil {
		t.Fatalf("init DRA: %v", err)
	}

	// 3. Derive token from chain (must match init token)
	derived, err := DeriveTokenFromChain(init.ChainKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if derived != init.McpToken {
		t.Errorf("DeriveTokenFromChain != init token:\n  %s\n  %s", derived, init.McpToken)
	}

	// 4. Advance chain (symmetric ratchet)
	chainKey1, advToken, err := AdvanceChain(init.ChainKey)
	if err != nil {
		t.Fatalf("advance: %v", err)
	}
	if advToken != init.McpToken {
		t.Errorf("AdvanceChain token should equal init token (derives before advancing)")
	}

	// 5. Token from advanced chain
	token1, err := DeriveTokenFromChain(chainKey1)
	if err != nil {
		t.Fatalf("derive from chain1: %v", err)
	}
	if token1 == init.McpToken {
		t.Error("token1 should differ from token0")
	}

	// 6. DH ratchet step
	ratchetRoot, ratchetChain, err := RatchetStep(init.RootKey, ss1)
	if err != nil {
		t.Fatalf("ratchet: %v", err)
	}

	// 7. Token from ratcheted chain
	ratchetToken, err := DeriveTokenFromChain(ratchetChain)
	if err != nil {
		t.Fatalf("derive from ratcheted chain: %v", err)
	}

	// Print all test vectors
	t.Log("=== CROSS-PLATFORM TEST VECTORS ===")
	t.Log("--- INPUTS ---")
	t.Logf("alice_priv   = %s", alicePrivB64)
	t.Logf("alice_pub    = %s", alicePubB64)
	t.Logf("bob_priv     = %s", bobPrivB64)
	t.Logf("bob_pub      = %s", bobPubB64)
	t.Log("--- EXPECTED OUTPUTS ---")
	t.Logf("shared_secret    = %s", ssB64)
	t.Logf("root_key_0       = %s", init.RootKey)
	t.Logf("chain_key_0      = %s", init.ChainKey)
	t.Logf("mcp_token_0      = %s", init.McpToken)
	t.Logf("chain_key_1      = %s", chainKey1)
	t.Logf("mcp_token_1      = %s", token1)
	t.Logf("ratchet_root     = %s", ratchetRoot)
	t.Logf("ratchet_chain    = %s", ratchetChain)
	t.Logf("ratchet_token    = %s", ratchetToken)
}
