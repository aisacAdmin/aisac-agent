// Package types defines shared types used across the AISAC agent.
package types

import "time"

// ActionStatus represents the status of an action execution.
type ActionStatus string

const (
	StatusPending    ActionStatus = "pending"
	StatusRunning    ActionStatus = "running"
	StatusSuccess    ActionStatus = "success"
	StatusFailed     ActionStatus = "failed"
	StatusTimeout    ActionStatus = "timeout"
	StatusCancelled  ActionStatus = "cancelled"
)

// ActionType represents the type of security action.
type ActionType string

const (
	// Firewall/Network actions
	ActionBlockIP         ActionType = "block_ip"
	ActionUnblockIP       ActionType = "unblock_ip"
	ActionIsolateHost     ActionType = "isolate_host"
	ActionUnisolateHost   ActionType = "unisolate_host"

	// User management actions
	ActionDisableUser     ActionType = "disable_user"
	ActionEnableUser      ActionType = "enable_user"

	// Process management actions
	ActionKillProcess     ActionType = "kill_process"

	// Investigation actions
	ActionDNSLookup         ActionType = "dns_lookup"
	ActionSearchIOC         ActionType = "search_ioc"
	ActionCheckHash         ActionType = "check_hash"
	ActionCheckIPReputation ActionType = "check_ip_reputation"

	// Forensics actions
	ActionCollectForensics ActionType = "collect_forensics"
	ActionThreatHunt       ActionType = "threat_hunt"
)

// Platform represents the target platform for actions.
type Platform string

const (
	PlatformLinux      Platform = "linux"
	PlatformWindows    Platform = "windows"
	PlatformDarwin     Platform = "darwin"
	PlatformPfSense    Platform = "pfsense"
	PlatformPaloAlto   Platform = "paloalto"
	PlatformFortigate  Platform = "fortigate"
)

// AgentInfo contains information about an agent.
type AgentInfo struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Platform  Platform  `json:"platform"`
	Version   string    `json:"version"`
	IP        string    `json:"ip"`
	LastSeen  time.Time `json:"last_seen"`
	Status    string    `json:"status"`
	Labels    []string  `json:"labels,omitempty"`
}

// ActionResult contains the result of an action execution.
type ActionResult struct {
	Success   bool                   `json:"success"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Artifacts []Artifact             `json:"artifacts,omitempty"`
}

// Artifact represents a file or data artifact collected during an action.
type Artifact struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Path     string `json:"path,omitempty"`
	Size     int64  `json:"size"`
	Checksum string `json:"checksum,omitempty"`
}

// ActionContext provides context for action execution.
type ActionContext struct {
	ExecutionID string
	CommandID   string
	AgentID     string
	Timeout     time.Duration
	DryRun      bool
}
