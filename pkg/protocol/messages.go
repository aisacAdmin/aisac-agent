// Package protocol defines the communication protocol between server and agents.
package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cisec/aisac-agent/pkg/types"
)

// MessageType represents the type of protocol message.
type MessageType string

const (
	// Server -> Agent messages
	MessageTypeCommand    MessageType = "command"
	MessageTypePing       MessageType = "ping"
	MessageTypeConfig     MessageType = "config_update"
	MessageTypeCancel     MessageType = "cancel"

	// Agent -> Server messages
	MessageTypeResponse   MessageType = "response"
	MessageTypePong       MessageType = "pong"
	MessageTypeHeartbeat  MessageType = "heartbeat"
	MessageTypeRegister   MessageType = "register"
)

// Message is the base protocol message.
type Message struct {
	ID        string          `json:"id"`
	Type      MessageType     `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Command represents an action command from server to agent.
type Command struct {
	ID            string                 `json:"id"`
	Action        types.ActionType       `json:"action"`
	Parameters    map[string]interface{} `json:"parameters"`
	ExecutionID   string                 `json:"execution_id"`
	TimeoutSeconds int                   `json:"timeout_seconds"`
	Priority      int                    `json:"priority,omitempty"`
}

// Response represents an action response from agent to server.
type Response struct {
	ID              string             `json:"id"`
	CommandID       string             `json:"command_id"`
	Status          types.ActionStatus `json:"status"`
	Result          types.ActionResult `json:"result"`
	ExecutionTimeMs int64              `json:"execution_time_ms"`
	Timestamp       time.Time          `json:"timestamp"`
}

// Heartbeat represents a periodic heartbeat from agent to server.
type Heartbeat struct {
	AgentID     string           `json:"agent_id"`
	Timestamp   time.Time        `json:"timestamp"`
	Status      string           `json:"status"`
	Metrics     *AgentMetrics    `json:"metrics,omitempty"`
	ActiveTasks []string         `json:"active_tasks,omitempty"`
}

// AgentMetrics contains agent resource metrics.
type AgentMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	Uptime        int64   `json:"uptime_seconds"`
}

// RegisterRequest is sent when an agent connects to the server.
type RegisterRequest struct {
	AgentInfo    types.AgentInfo  `json:"agent_info"`
	Capabilities []string         `json:"capabilities"`
	Version      string           `json:"version"`
}

// RegisterResponse is sent by the server after registration.
type RegisterResponse struct {
	Accepted      bool     `json:"accepted"`
	Message       string   `json:"message,omitempty"`
	ServerVersion string   `json:"server_version"`
	Config        []byte   `json:"config,omitempty"`
}

// CancelCommand requests cancellation of a running command.
type CancelCommand struct {
	CommandID string `json:"command_id"`
	Reason    string `json:"reason,omitempty"`
}

// NewMessage creates a new protocol message with the given type and payload.
func NewMessage(msgType MessageType, payload interface{}) (*Message, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &Message{
		ID:        generateID(),
		Type:      msgType,
		Timestamp: time.Now().UTC(),
		Payload:   payloadBytes,
	}, nil
}

// ParsePayload unmarshals the message payload into the given target.
func (m *Message) ParsePayload(target interface{}) error {
	return json.Unmarshal(m.Payload, target)
}

// generateID generates a cryptographically secure unique message ID.
// SECURITY: Uses crypto/rand instead of timestamp to prevent prediction attacks.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID only if crypto/rand fails
		return "msg-" + time.Now().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}
