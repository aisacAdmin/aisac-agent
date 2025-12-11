package actions

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/pkg/types"
)

// CheckHashAction checks a file hash against threat intelligence and local files.
type CheckHashAction struct {
	logger     zerolog.Logger
	httpClient *http.Client
}

// NewCheckHashAction creates a new CheckHashAction.
func NewCheckHashAction(logger zerolog.Logger) *CheckHashAction {
	return &CheckHashAction{
		logger: logger.With().Str("action", "check_hash").Logger(),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the action name.
func (a *CheckHashAction) Name() types.ActionType {
	return types.ActionCheckHash
}

// Validate validates the parameters.
func (a *CheckHashAction) Validate(params map[string]interface{}) error {
	hash, ok := params["hash"].(string)
	if !ok || hash == "" {
		return fmt.Errorf("hash is required")
	}

	// Validate hash format
	hash = strings.ToLower(hash)
	hashLen := len(hash)

	validLengths := map[int]string{
		32:  "md5",
		40:  "sha1",
		64:  "sha256",
		128: "sha512",
	}

	if _, valid := validLengths[hashLen]; !valid {
		return fmt.Errorf("invalid hash length: %d (expected 32/40/64/128 for md5/sha1/sha256/sha512)", hashLen)
	}

	// Check if it's valid hex
	if _, err := hex.DecodeString(hash); err != nil {
		return fmt.Errorf("hash must be hexadecimal: %v", err)
	}

	return nil
}

// HashMatch represents a file that matches the searched hash.
type HashMatch struct {
	FilePath     string    `json:"file_path"`
	Size         int64     `json:"size"`
	ModifiedTime time.Time `json:"modified_time"`
	Permissions  string    `json:"permissions"`
}

// ThreatIntelResult represents threat intelligence lookup results.
type ThreatIntelResult struct {
	Source       string `json:"source"`
	IsMalicious  bool   `json:"is_malicious"`
	DetectionRate string `json:"detection_rate,omitempty"`
	MalwareFamily string `json:"malware_family,omitempty"`
	FirstSeen    string `json:"first_seen,omitempty"`
	LastSeen     string `json:"last_seen,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Execute checks the hash against local files and threat intelligence.
func (a *CheckHashAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	hash := strings.ToLower(params["hash"].(string))

	// Determine hash type
	hashType := detectHashType(hash)

	// Get search paths (default to common locations)
	searchPaths := []string{"/tmp", "/var/tmp", "/home", "/root", "/opt"}
	if paths, ok := params["search_paths"].([]interface{}); ok {
		searchPaths = make([]string, len(paths))
		for i, p := range paths {
			searchPaths[i] = p.(string)
		}
	}

	// Check if we should search local files
	searchLocal := true
	if sl, ok := params["search_local"].(bool); ok {
		searchLocal = sl
	}

	// Get API keys for threat intel (optional)
	var vtAPIKey, otxAPIKey string
	if key, ok := params["virustotal_api_key"].(string); ok {
		vtAPIKey = key
	}
	if key, ok := params["otx_api_key"].(string); ok {
		otxAPIKey = key
	}

	a.logger.Info().
		Str("hash", hash).
		Str("hash_type", hashType).
		Bool("search_local", searchLocal).
		Msg("Checking hash")

	var localMatches []HashMatch
	var threatIntelResults []ThreatIntelResult

	// Search local files if enabled
	if searchLocal {
		localMatches = a.searchLocalFiles(ctx, hash, hashType, searchPaths)
	}

	// Query threat intelligence APIs
	if vtAPIKey != "" {
		vtResult := a.queryVirusTotal(ctx, hash, vtAPIKey)
		threatIntelResults = append(threatIntelResults, vtResult)
	}

	if otxAPIKey != "" {
		otxResult := a.queryAlienVaultOTX(ctx, hash, otxAPIKey)
		threatIntelResults = append(threatIntelResults, otxResult)
	}

	// Query MalwareBazaar (no API key required)
	mbResult := a.queryMalwareBazaar(ctx, hash)
	threatIntelResults = append(threatIntelResults, mbResult)

	// Determine if hash is malicious based on threat intel
	isMalicious := false
	for _, result := range threatIntelResults {
		if result.IsMalicious {
			isMalicious = true
			break
		}
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("Hash check completed for %s", hash),
		Details: map[string]interface{}{
			"hash":                hash,
			"hash_type":           hashType,
			"is_malicious":        isMalicious,
			"local_files_found":   len(localMatches),
			"local_matches":       localMatches,
			"threat_intel":        threatIntelResults,
			"checked_at":          time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// detectHashType determines the hash type based on length.
func detectHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	case 128:
		return "sha512"
	default:
		return "unknown"
	}
}

// searchLocalFiles searches for files matching the given hash.
func (a *CheckHashAction) searchLocalFiles(ctx context.Context, targetHash, hashType string, searchPaths []string) []HashMatch {
	var matches []HashMatch
	maxFilesToCheck := 10000
	filesChecked := 0

	for _, basePath := range searchPaths {
		if filesChecked >= maxFilesToCheck {
			break
		}

		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err != nil || info == nil || info.IsDir() {
				return nil
			}

			// Skip very large files (> 100MB) and special files
			if info.Size() > 100*1024*1024 || info.Size() == 0 {
				return nil
			}

			filesChecked++
			if filesChecked >= maxFilesToCheck {
				return filepath.SkipAll
			}

			// Calculate hash
			fileHash, err := calculateFileHash(path, hashType)
			if err != nil {
				return nil
			}

			if fileHash == targetHash {
				matches = append(matches, HashMatch{
					FilePath:     path,
					Size:         info.Size(),
					ModifiedTime: info.ModTime(),
					Permissions:  info.Mode().String(),
				})
			}

			return nil
		})
	}

	return matches
}

// calculateFileHash calculates the hash of a file.
func calculateFileHash(filePath, hashType string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hash string
	switch hashType {
	case "md5":
		h := md5.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(h.Sum(nil))
	case "sha1":
		h := sha1.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(h.Sum(nil))
	case "sha256":
		h := sha256.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(h.Sum(nil))
	default:
		return "", fmt.Errorf("unsupported hash type: %s", hashType)
	}

	return hash, nil
}

// queryVirusTotal queries VirusTotal API for hash information.
func (a *CheckHashAction) queryVirusTotal(ctx context.Context, hash, apiKey string) ThreatIntelResult {
	result := ThreatIntelResult{Source: "VirusTotal"}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("x-apikey", apiKey)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		result.IsMalicious = false
		return result
	}

	if resp.StatusCode != 200 {
		result.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
		return result
	}

	var vtResponse struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				PopularThreatClassification struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
				FirstSubmissionDate int64 `json:"first_submission_date"`
				LastAnalysisDate    int64 `json:"last_analysis_date"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err != nil {
		result.Error = err.Error()
		return result
	}

	stats := vtResponse.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected

	result.IsMalicious = stats.Malicious > 0
	result.DetectionRate = fmt.Sprintf("%d/%d", stats.Malicious, total)
	result.MalwareFamily = vtResponse.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel

	if vtResponse.Data.Attributes.FirstSubmissionDate > 0 {
		result.FirstSeen = time.Unix(vtResponse.Data.Attributes.FirstSubmissionDate, 0).Format(time.RFC3339)
	}
	if vtResponse.Data.Attributes.LastAnalysisDate > 0 {
		result.LastSeen = time.Unix(vtResponse.Data.Attributes.LastAnalysisDate, 0).Format(time.RFC3339)
	}

	return result
}

// queryAlienVaultOTX queries AlienVault OTX for hash information.
func (a *CheckHashAction) queryAlienVaultOTX(ctx context.Context, hash, apiKey string) ThreatIntelResult {
	result := ThreatIntelResult{Source: "AlienVault OTX"}

	hashType := detectHashType(hash)
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/file/%s/general", hash)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("X-OTX-API-KEY", apiKey)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		result.IsMalicious = false
		return result
	}

	if resp.StatusCode != 200 {
		result.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
		return result
	}

	var otxResponse struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
		Analysis map[string]interface{} `json:"analysis"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&otxResponse); err != nil {
		result.Error = err.Error()
		return result
	}

	// If hash appears in threat pulses, consider it suspicious
	result.IsMalicious = otxResponse.PulseInfo.Count > 0
	if result.IsMalicious {
		result.DetectionRate = fmt.Sprintf("%d pulses", otxResponse.PulseInfo.Count)
	}

	_ = hashType // Suppress unused variable warning

	return result
}

// queryMalwareBazaar queries MalwareBazaar for hash information.
func (a *CheckHashAction) queryMalwareBazaar(ctx context.Context, hash string) ThreatIntelResult {
	result := ThreatIntelResult{Source: "MalwareBazaar"}

	url := "https://mb-api.abuse.ch/api/v1/"
	body := strings.NewReader(fmt.Sprintf("query=get_info&hash=%s", hash))

	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	var mbResponse struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			Signature   string `json:"signature"`
			FirstSeen   string `json:"first_seen"`
			LastSeen    string `json:"last_seen"`
			FileType    string `json:"file_type"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&mbResponse); err != nil {
		result.Error = err.Error()
		return result
	}

	if mbResponse.QueryStatus == "ok" && len(mbResponse.Data) > 0 {
		result.IsMalicious = true
		result.MalwareFamily = mbResponse.Data[0].Signature
		result.FirstSeen = mbResponse.Data[0].FirstSeen
		result.LastSeen = mbResponse.Data[0].LastSeen
	}

	return result
}
